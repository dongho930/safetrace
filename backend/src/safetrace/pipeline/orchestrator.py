"""파이프라인 오케스트레이터: 후보 발굴 → 접근 전 검사 → 조사 큐 → (Worker) → 증거 → AI → 평판 → 패키지 → 재큐잉.

사전준비 단계는 인메모리 상태를 쓰고, 1주차에 PostgreSQL(상태 원본)·Redis Streams(작업 전달)로 교체한다.
상태 전이·감사로그·이벤트 발행 지점은 교체 후에도 그대로 유지되도록 한 곳(_set_status)에 모았다.
"""

from __future__ import annotations

import asyncio
import base64
import itertools
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from safetrace.ai.engine import DecisionEngine
from safetrace.discovery.policy import Budget, Frontier
from safetrace.evidence.ledger import EvidenceLedger
from safetrace.pipeline.events import EventBus
from safetrace.pipeline.package import build_package
from safetrace.reputation.safebrowsing import SafeBrowsingClient
from safetrace.schemas import (
    AIAnalysis,
    AuditLog,
    Candidate,
    CandidateStatus,
    Case,
    Decision,
    EvidenceType,
    Observation,
    PipelineEvent,
    Reputation,
    Review,
    SeedSource,
    Stage,
    StageStatus,
    new_id,
)
from safetrace.security.url_policy import PolicyViolation, UrlPolicy

log = logging.getLogger(__name__)

STATUS_STAGE = {
    CandidateStatus.DISCOVERED: (Stage.DISCOVERY, StageStatus.DONE),
    CandidateStatus.SCREENING: (Stage.SCREENING, StageStatus.RUNNING),
    CandidateStatus.QUEUED: (Stage.INVESTIGATION, StageStatus.WAITING),
    CandidateStatus.INVESTIGATING: (Stage.INVESTIGATION, StageStatus.RUNNING),
    CandidateStatus.ANALYZING: (Stage.ANALYSIS, StageStatus.RUNNING),
    CandidateStatus.PACKAGING: (Stage.PACKAGE, StageStatus.RUNNING),
    CandidateStatus.REVIEW_REQUIRED: (Stage.REVIEW, StageStatus.WAITING),
    CandidateStatus.DECIDED: (Stage.REVIEW, StageStatus.DONE),
    CandidateStatus.SKIPPED: (Stage.DISCOVERY, StageStatus.DONE),
    CandidateStatus.BLOCKED: (Stage.SCREENING, StageStatus.FAILED),
    CandidateStatus.UNREACHABLE: (Stage.INVESTIGATION, StageStatus.FAILED),
    CandidateStatus.FAILED: (Stage.INVESTIGATION, StageStatus.FAILED),
}
ALLOWED_ARTIFACTS = {EvidenceType.SCREENSHOT, EvidenceType.HTML, EvidenceType.OBSERVATION,
                     EvidenceType.VIDEO, EvidenceType.HAR}
MAX_ARTIFACT_BYTES = {
    EvidenceType.SCREENSHOT: 10_000_000, EvidenceType.HTML: 5_000_000, EvidenceType.OBSERVATION: 2_000_000,
    EvidenceType.VIDEO: 60_000_000, EvidenceType.HAR: 60_000_000,
}


class OrchestratorError(Exception):
    def __init__(self, code: str, http_status: int = 400) -> None:
        super().__init__(code)
        self.code = code
        self.http_status = http_status


@dataclass
class Lease:
    job_id: str
    candidate_id: str
    worker_id: str
    leased_at: float


@dataclass
class Orchestrator:
    ledger: EvidenceLedger
    engine: DecisionEngine
    bus: EventBus
    policy: UrlPolicy
    safebrowsing: SafeBrowsingClient
    budget: Budget = field(default_factory=Budget)
    lease_timeout_s: float = 180.0

    cases: dict[str, Case] = field(default_factory=dict)
    candidates: dict[str, Candidate] = field(default_factory=dict)
    frontiers: dict[str, Frontier] = field(default_factory=dict)
    observations: dict[str, Observation] = field(default_factory=dict)
    analyses: dict[str, AIAnalysis] = field(default_factory=dict)
    reputations: dict[str, list[Reputation]] = field(default_factory=dict)
    reviews: dict[str, Review] = field(default_factory=dict)
    impersonates: dict[str, list[str]] = field(default_factory=dict)
    audit: list[AuditLog] = field(default_factory=list)
    leases: dict[str, Lease] = field(default_factory=dict)
    edges: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._queue: asyncio.PriorityQueue[tuple[float, int, str]] = asyncio.PriorityQueue()
        self._tie = itertools.count()
        self._tasks: set[asyncio.Task] = set()

    # ───────────── 공통 ─────────────

    def record_audit(self, actor: str, action: str, target: str, result: str = "OK", detail: str = "") -> None:
        self.audit.append(AuditLog(actor=actor[:256], action=action, target=target, result=result,
                                   detail=detail[:256]))

    def _emit(self, type_: str, cand: Candidate | None = None, data: dict | None = None,
              replayable: bool = True) -> None:
        stage = status = None
        if cand is not None:
            stage, status = STATUS_STAGE[cand.status]
        self.bus.publish(PipelineEvent(
            type=type_, case_id=cand.case_id if cand else None,
            candidate_id=cand.candidate_id if cand else None, stage=stage, status=status,
            data=data or {},
        ), replayable=replayable)

    def _set_status(self, cand: Candidate, status: CandidateStatus, reason: str = "",
                    actor: str = "system:pipeline") -> None:
        prev = cand.status
        cand.status = status
        cand.status_reason = reason[:256]
        self.record_audit(actor, f"candidate.status.{status.value}", cand.candidate_id, detail=f"{prev.value}→{reason}")
        self._emit("candidate.status", cand, {"from": prev.value, "to": status.value, "reason": reason[:256],
                                              "url": cand.normalized_url, "priority": cand.priority,
                                              "depth": cand.depth})
        self._emit("pipeline.stats", data=self.stats())

    def _spawn(self, coro) -> None:
        t = asyncio.create_task(coro)
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)

    def stats(self) -> dict[str, int]:
        c = {s.value: 0 for s in CandidateStatus}
        for cand in self.candidates.values():
            c[cand.status.value] += 1
        return {
            "discovered": len(self.candidates),
            "waiting": c["QUEUED"] + c["SCREENING"] + c["DISCOVERED"],
            "investigating": c["INVESTIGATING"] + c["ANALYZING"] + c["PACKAGING"],
            "review_required": c["REVIEW_REQUIRED"],
            "decided": c["DECIDED"],
            "failed": c["FAILED"] + c["BLOCKED"] + c["UNREACHABLE"],
            "skipped": c["SKIPPED"],
            "cases": len(self.cases),
        }

    # ───────────── ⓪ 후보 접수·발굴 ─────────────

    async def submit(self, url: str, source: SeedSource, actor: str) -> Candidate:
        case = Case(source=source, original_url=url[:2048], submitted_by=actor)
        frontier = Frontier(case_id=case.case_id, budget=Budget(**vars(self.budget)))
        try:
            cand = frontier.seed(url, source)
        except PolicyViolation as exc:
            self.record_audit(actor, "case.submit", url[:200], "DENIED", exc.code)
            raise OrchestratorError(exc.code) from None
        self.cases[case.case_id] = case
        self.frontiers[case.case_id] = frontier
        cand.status = CandidateStatus.DISCOVERED
        self.candidates[cand.candidate_id] = cand
        self.record_audit(actor, "case.submit", case.case_id, detail=source.value)
        self._emit("candidate.discovered", cand, {"url": cand.normalized_url, "source": source.value,
                                                  "priority": cand.priority, "depth": 0})
        self._spawn(self._screen(cand))
        return cand

    async def _screen(self, cand: Candidate) -> None:
        self._set_status(cand, CandidateStatus.SCREENING)
        try:
            n, ips = await self.policy.check_url(cand.normalized_url)
        except PolicyViolation as exc:
            status = (CandidateStatus.UNREACHABLE if exc.code.startswith("DNS_")
                      else CandidateStatus.BLOCKED)
            self._set_status(cand, status, exc.code)
            return
        self._set_status(cand, CandidateStatus.QUEUED, f"resolved {len(ips)} addr")
        await self._queue.put((-cand.priority, next(self._tie), cand.candidate_id))

    # ───────────── ① Worker 작업 임대·결과 수신 ─────────────

    async def lease(self, worker_id: str, wait_s: float = 20.0) -> dict[str, Any] | None:
        self._reap_leases()
        try:
            _, _, cid = await asyncio.wait_for(self._queue.get(), wait_s)
        except TimeoutError:
            return None
        cand = self.candidates[cid]
        if cand.status != CandidateStatus.QUEUED:
            return None
        job = Lease(job_id=new_id("job"), candidate_id=cid, worker_id=worker_id, leased_at=time.monotonic())
        self.leases[job.job_id] = job
        self._set_status(cand, CandidateStatus.INVESTIGATING, f"worker {worker_id[:32]}")
        return {"job_id": job.job_id, "candidate_id": cid, "url": cand.normalized_url}

    def _reap_leases(self) -> None:
        now = time.monotonic()
        for job_id, lease in list(self.leases.items()):
            if now - lease.leased_at > self.lease_timeout_s:
                del self.leases[job_id]
                cand = self.candidates[lease.candidate_id]
                self._set_status(cand, CandidateStatus.FAILED, "LEASE_TIMEOUT")

    def _take_lease(self, job_id: str, worker_id: str) -> Lease:
        lease = self.leases.get(job_id)
        if lease is None or lease.worker_id != worker_id:
            raise OrchestratorError("JOB_NOT_FOUND", 404)
        return lease

    def push_frame(self, job_id: str, worker_id: str, jpeg: bytes) -> None:
        lease = self._take_lease(job_id, worker_id)
        if not jpeg.startswith(b"\xff\xd8") or len(jpeg) > 400_000:
            raise OrchestratorError("BAD_FRAME")
        cand = self.candidates[lease.candidate_id]
        self._emit("investigation.frame", cand, {"jpeg_b64": base64.b64encode(jpeg).decode()}, replayable=False)

    def push_step(self, job_id: str, worker_id: str, step: str, data: dict) -> None:
        lease = self._take_lease(job_id, worker_id)
        cand = self.candidates[lease.candidate_id]
        safe = {k: str(v)[:300] for k, v in list(data.items())[:10]}
        self._emit("investigation.step", cand, {"step": step[:32], **safe})

    async def complete(self, job_id: str, worker_id: str, obs: Observation,
                       artifacts: dict[EvidenceType, bytes]) -> None:
        lease = self._take_lease(job_id, worker_id)
        del self.leases[job_id]
        cand = self.candidates[lease.candidate_id]
        if obs.candidate_id != cand.candidate_id:
            self._set_status(cand, CandidateStatus.FAILED, "RESULT_MISMATCH")
            raise OrchestratorError("RESULT_MISMATCH")
        for et, data in artifacts.items():
            if et not in ALLOWED_ARTIFACTS or len(data) > MAX_ARTIFACT_BYTES[et]:
                self._set_status(cand, CandidateStatus.FAILED, f"ARTIFACT_REJECTED {et}")
                raise OrchestratorError("ARTIFACT_REJECTED")
        self.observations[cand.candidate_id] = obs

        # 증거 저장(해시 체인 + 분리 서명)
        evidence_ids: dict[EvidenceType, str] = {}
        artifacts = {**artifacts, EvidenceType.OBSERVATION: obs.model_dump_json(indent=2).encode()}
        for et in (EvidenceType.SCREENSHOT, EvidenceType.HTML, EvidenceType.OBSERVATION,
                   EvidenceType.VIDEO, EvidenceType.HAR):
            if et in artifacts:
                ev = await self.ledger.append(case_id=cand.case_id, candidate_id=cand.candidate_id,
                                              etype=et, data=artifacts[et])
                evidence_ids[et] = ev.evidence_id
                self._emit("evidence.stored", cand, {"evidence_id": ev.evidence_id, "type": et.value,
                                                     "sha256": ev.sha256, "seq": ev.seq})

        if not obs.reachable and not obs.dom_summary.text_excerpt:
            reason = ",".join(obs.policy_blocks + obs.errors)[:200] or "UNREACHABLE"
            blocked = any(c.startswith(("IP_", "URL_", "REDIRECT_LIMIT")) for c in obs.policy_blocks)
            self._set_status(cand, CandidateStatus.BLOCKED if blocked else CandidateStatus.UNREACHABLE, reason)
            self.record_audit("system:pipeline", "investigation.unreachable", cand.candidate_id, detail=reason)
            return

        # ② AI 분석
        self._set_status(cand, CandidateStatus.ANALYZING)
        analysis = await asyncio.to_thread(self.engine.analyze, obs, evidence_ids)
        self.analyses[cand.candidate_id] = analysis
        self._emit("analysis.done", cand, {
            "state": analysis.state.value,
            "top": [{"type": t.type.value, "confidence": t.confidence} for t in analysis.threat_types[:3]],
        })

        # ③ 평판 조회 + 패키지
        self._set_status(cand, CandidateStatus.PACKAGING)
        urls = [cand.normalized_url] + ([obs.final_url] if obs.final_url else [])
        reps = await self.safebrowsing.lookup(urls)
        self.reputations[cand.candidate_id] = reps
        self._emit("reputation.done", cand, {"results": [r.result.value for r in reps]})

        # ⓪ 관찰 후보 재큐잉
        frontier = self.frontiers[cand.case_id]
        res = frontier.expand(cand, obs)
        self.impersonates[cand.candidate_id] = res.impersonates
        for dom in res.impersonates:
            self.edges.append({"from": cand.candidate_id, "to": dom, "relation": "IMPERSONATES"})
        for hop in res.traversed:
            self.edges.append({"from": cand.candidate_id, "to": hop, "relation": "TRAVERSED"})
        for child in res.queued:
            child.status = CandidateStatus.DISCOVERED
            self.candidates[child.candidate_id] = child
            self.edges.append({"from": cand.candidate_id, "to": child.candidate_id,
                               "relation": child.relation.value})
            self._emit("candidate.discovered", child, {
                "url": child.normalized_url, "source": child.source.value, "priority": child.priority,
                "depth": child.depth, "from": cand.candidate_id, "relation": child.relation.value,
            })
            self._spawn(self._screen(child))
        self._emit("discovery.expanded", cand, {"queued": len(res.queued), "skipped": dict(res.skipped),
                                                "impersonates": res.impersonates})
        self._set_status(cand, CandidateStatus.REVIEW_REQUIRED, analysis.state.value)

    def fail(self, job_id: str, worker_id: str, code: str) -> None:
        lease = self._take_lease(job_id, worker_id)
        del self.leases[job_id]
        self._set_status(self.candidates[lease.candidate_id], CandidateStatus.FAILED, code[:64])

    # ───────────── 담당자 검토 ─────────────

    def decide(self, candidate_id: str, actor_id: str, role: str, decision: Decision, reason: str) -> Review:
        cand = self.candidates.get(candidate_id)
        if cand is None:
            raise OrchestratorError("NOT_FOUND", 404)
        if role != "reviewer":
            # 자동화 계정·AI·조사자 계정은 판정을 확정할 수 없다(R7).
            self.record_audit(actor_id, "review.decide", candidate_id, "DENIED", f"role={role}")
            raise OrchestratorError("FORBIDDEN_ROLE", 403)
        if cand.status != CandidateStatus.REVIEW_REQUIRED:
            raise OrchestratorError("INVALID_STATE", 409)
        review = Review(candidate_id=candidate_id, reviewer_id=actor_id, decision=decision, reason=reason)
        self.reviews[candidate_id] = review
        self._set_status(cand, CandidateStatus.DECIDED, decision.value, actor=actor_id)
        return review

    async def package(self, candidate_id: str) -> dict[str, Any]:
        cand = self.candidates.get(candidate_id)
        if cand is None:
            raise OrchestratorError("NOT_FOUND", 404)
        evidence = await self.ledger.list_for_candidate(candidate_id)
        verification = await self.ledger.verify(candidate_id)
        return build_package(cand, self.observations.get(candidate_id), evidence, verification,
                             self.analyses.get(candidate_id), self.reputations.get(candidate_id, []),
                             self.reviews.get(candidate_id), self.impersonates.get(candidate_id, []))
