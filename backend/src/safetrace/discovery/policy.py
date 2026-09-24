"""⓪ Candidate Discovery 정책(설계 확정본, docs/05_candidate_discovery_policy.md).

관찰된 링크를 그대로 재큐잉하지 않는다.
1) 정규화 실패·중복(visited)·허용목록은 재큐잉하지 않는다(허용목록은 IMPERSONATES 관계로만 기록).
2) 나머지는 관계 유형·신규 등록·유사 도메인·입력 폼 연결 가점, 공용 인프라·깊이 감점으로 점수화한다.
3) 깊이·사건당 후보 수·도메인당 후보 수 예산 안에서 점수 상위 후보만 큐에 넣는다.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field

from safetrace.ai.features import SUSPICIOUS_TLDS
from safetrace.discovery.allowlist import is_allowlisted, is_common_infra
from safetrace.discovery.similarity import lookalike_target
from safetrace.schemas import (
    Candidate,
    CandidateStatus,
    Observation,
    Relation,
    ScoreReason,
    SeedSource,
)
from safetrace.security.url_policy import PolicyViolation, normalize_url

MIN_PRIORITY = 1.0
RELATION_BASE = {
    Relation.REDIRECT: 3.0,
    Relation.FORM_ACTION: 3.0,
    Relation.LINK: 1.0,
    Relation.SCRIPT: 0.5,
    Relation.RESOURCE: 0.3,
}
SEED_PRIORITY = {SeedSource.REPORT: 10.0, SeedSource.KISA: 8.0, SeedSource.SEARCH_API: 6.0}

# 등록일(일) 조회기. RDAP 연동은 1~2주차(docs/05 §4). None 이면 가점 없음.
DomainAgeLookup = Callable[[str], int | None]


@dataclass
class Budget:
    max_depth: int = 2
    max_candidates: int = 30
    max_per_domain: int = 5


@dataclass
class ExpandResult:
    queued: list[Candidate] = field(default_factory=list)
    impersonates: list[str] = field(default_factory=list)  # 사칭 대상(허용목록) 도메인
    traversed: list[str] = field(default_factory=list)  # 조사 중 거쳐 간 다른 도메인 hop(재조사하지 않음)
    skipped: Counter = field(default_factory=Counter)  # 사유별 건수


@dataclass
class Frontier:
    """사건 단위 탐색 상태: visited 집합·도메인별 건수·예산."""

    case_id: str
    budget: Budget = field(default_factory=Budget)
    visited: set[str] = field(default_factory=set)
    per_domain: Counter = field(default_factory=Counter)
    total: int = 0

    def seed(self, url: str, source: SeedSource) -> Candidate:
        n = normalize_url(url)
        self.visited.add(n.idempotency_key)
        self.per_domain[n.registrable_domain] += 1
        self.total += 1
        return Candidate(
            case_id=self.case_id, source=source, original_url=url[:2048], normalized_url=n.url,
            registrable_domain=n.registrable_domain, relation=Relation.SEED, depth=0,
            priority=SEED_PRIORITY.get(source, 5.0), idempotency_key=n.idempotency_key,
            status=CandidateStatus.QUEUED,
        )

    def expand(self, parent: Candidate, obs: Observation, age_lookup: DomainAgeLookup | None = None
               ) -> ExpandResult:
        res = ExpandResult()
        depth = parent.depth + 1
        if depth > self.budget.max_depth:
            res.skipped["DEPTH_LIMIT"] += len(obs.observed_links)
            return res

        # 부모 조사 중 이미 거쳐 간 리다이렉트 hop·최종 URL 은 조사된 것으로 본다(중복 조사 0).
        # 다른 등록 도메인을 경유했다면 관계 그래프에만 남긴다.
        for hop_url in [h.url for h in obs.redirect_chain] + ([obs.final_url] if obs.final_url else []):
            try:
                hop = normalize_url(hop_url)
            except PolicyViolation:
                continue
            if hop.idempotency_key not in self.visited:
                self.visited.add(hop.idempotency_key)
                if hop.registrable_domain != parent.registrable_domain and hop.url not in res.traversed:
                    res.traversed.append(hop.url)

        parent_has_sensitive_form = any(f.has_password or f.has_card_like or f.has_id_number_like
                                        for f in obs.forms)
        scored: dict[str, Candidate] = {}
        for link in obs.observed_links:
            try:
                n = normalize_url(link.url)
            except PolicyViolation:
                res.skipped["INVALID_URL"] += 1
                continue
            if is_allowlisted(n.host):
                if n.registrable_domain not in res.impersonates:
                    res.impersonates.append(n.registrable_domain)
                res.skipped["ALLOWLISTED"] += 1
                continue
            key = n.idempotency_key
            if key in self.visited:
                res.skipped["DUPLICATE"] += 1
                continue

            reasons = [ScoreReason(code=f"REL_{link.relation.value}", weight=RELATION_BASE.get(link.relation, 0.5))]
            target = lookalike_target(n.host)
            if target:
                reasons.append(ScoreReason(code="LOOKALIKE", weight=3.0, detail=f"~{target}"))
            if n.host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
                reasons.append(ScoreReason(code="SUSPICIOUS_TLD", weight=1.0))
            if "xn--" in n.host:
                reasons.append(ScoreReason(code="PUNYCODE", weight=1.0))
            if parent_has_sensitive_form:
                reasons.append(ScoreReason(code="FROM_SENSITIVE_FORM_PAGE", weight=1.5))
            if age_lookup is not None:
                age = age_lookup(n.registrable_domain)
                if age is not None and age <= 90:
                    reasons.append(ScoreReason(code="NEWLY_REGISTERED", weight=2.0, detail=f"{age}d"))
            if is_common_infra(n.host):
                reasons.append(ScoreReason(code="COMMON_INFRA", weight=-3.0))
            if n.registrable_domain == parent.registrable_domain and link.relation == Relation.LINK:
                reasons.append(ScoreReason(code="SAME_SITE_LINK", weight=-1.0))
            reasons.append(ScoreReason(code="DEPTH", weight=-0.5 * depth))
            priority = round(sum(r.weight for r in reasons), 3)

            prev = scored.get(key)
            if prev is not None and prev.priority >= priority:
                continue
            scored[key] = Candidate(
                case_id=self.case_id, source=SeedSource.DISCOVERED, original_url=link.url[:2048],
                normalized_url=n.url, registrable_domain=n.registrable_domain,
                discovered_from=parent.candidate_id, relation=link.relation, depth=depth,
                priority=priority, score_reasons=reasons, idempotency_key=key,
            )

        for cand in sorted(scored.values(), key=lambda c: -c.priority):
            if cand.priority < MIN_PRIORITY:
                res.skipped["LOW_PRIORITY"] += 1
                continue
            if self.total >= self.budget.max_candidates:
                res.skipped["CASE_BUDGET"] += 1
                continue
            if self.per_domain[cand.registrable_domain] >= self.budget.max_per_domain:
                res.skipped["DOMAIN_BUDGET"] += 1
                continue
            self.visited.add(cand.idempotency_key)
            self.per_domain[cand.registrable_domain] += 1
            self.total += 1
            cand.status = CandidateStatus.QUEUED
            res.queued.append(cand)
        return res
