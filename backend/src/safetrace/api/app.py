"""SafeTrace API: 판정 콘솔용 API + 실시간 SSE + Worker 전용 수집(ingest) API.

- 콘솔 API(/api/*): 토큰 인증 + RBAC. 판정 확정은 reviewer 역할만.
- 수집 API(/ingest/*): Worker 토큰만. 운영 배치에서는 ingest-gw 가 /ingest/ 경로만 Worker 망에 노출한다.
- 오류 응답은 일반화된 코드만 반환하고, 운영 모드에서 문서·디버그 엔드포인트를 끈다.
"""


import asyncio
import contextlib
import hmac
import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from safetrace.ai.engine import DecisionEngine
from safetrace.api.auth import ANY, SUBMITTERS, Principal, Role, TokenRegistry, require, set_registry
from safetrace.config import Settings, get_settings
from safetrace.discovery.policy import Budget
from safetrace.evidence.ledger import EvidenceLedger, sha256_bytes
from safetrace.evidence.signer_client import SignerClient
from safetrace.ingest.kisa import load_csv
from safetrace.pipeline.events import EventBus
from safetrace.pipeline.orchestrator import Orchestrator, OrchestratorError
from safetrace.reputation.safebrowsing import SafeBrowsingClient
from safetrace.schemas import Decision, EvidenceType, Observation, SeedSource, SubmitUrl
from safetrace.security.url_policy import UrlPolicy

log = logging.getLogger("safetrace.api")

MAX_JSON = 2_000_000
MAX_CSV = 20_000_000
CONTENT_TYPES = {
    EvidenceType.SCREENSHOT: ("image/png", "inline"),
    EvidenceType.VIDEO: ("video/webm", "inline"),
    EvidenceType.HTML: ("text/plain; charset=utf-8", "attachment"),  # 수집 HTML 은 절대 렌더링하지 않는다
    EvidenceType.OBSERVATION: ("application/json", "attachment"),
    EvidenceType.HAR: ("application/json", "attachment"),
}
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; img-src 'self' data:; media-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Decision
    reason: Annotated[str, Field(min_length=5, max_length=2000)]


class LeaseIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    worker_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")]


class StepIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    step: Annotated[str, Field(pattern=r"^[a-z_]{1,32}$")]
    data: dict[str, Any] = {}


class FailIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: Annotated[str, Field(pattern=r"^[A-Z0-9_]{1,64}$")]


async def read_limited(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > limit):
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "too large")
    buf = bytearray()
    async for chunk in request.stream():
        buf += chunk
        if len(buf) > limit:
            raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "too large")
    return bytes(buf)


def build_orchestrator(settings: Settings) -> Orchestrator:
    data_dir = settings.data_dir
    signer = SignerClient(settings.signer_url, settings.signer_token.get_secret_value())
    ledger = EvidenceLedger(data_dir / "evidence", signer)
    classifier = None
    if settings.env != "test":
        from safetrace.ai.zeroshot import load_default  # 선택 의존성

        classifier = load_default() if _zeroshot_enabled() else None
    return Orchestrator(
        ledger=ledger,
        engine=DecisionEngine(classifier=classifier),
        bus=EventBus(),
        policy=UrlPolicy(allow_hostports=settings.allowed_test_hostports()),
        safebrowsing=SafeBrowsingClient(settings.safe_browsing_api_key.get_secret_value()),
        budget=Budget(max_depth=settings.max_depth, max_candidates=settings.max_candidates_per_case,
                      max_per_domain=settings.max_candidates_per_domain),
    )


def _zeroshot_enabled() -> bool:
    import os

    return os.environ.get("SAFETRACE_ZEROSHOT", "0") == "1"


def create_app(settings: Settings | None = None, orchestrator: Orchestrator | None = None,
               registry: TokenRegistry | None = None, inproc_worker: bool | None = None) -> FastAPI:
    settings = settings or get_settings()
    set_registry(registry or TokenRegistry.from_env())
    worker_token = settings.worker_token.get_secret_value()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.orch = orchestrator or build_orchestrator(settings)
        task = None
        import os

        run_inproc = inproc_worker if inproc_worker is not None else os.environ.get("SAFETRACE_INPROC_WORKER") == "1"
        if run_inproc:
            from safetrace.worker.main import LocalJobSource, make_agent, run_worker

            stop = asyncio.Event()
            task = asyncio.create_task(run_worker(LocalJobSource(app.state.orch), make_agent(settings, local=True),
                                                  "inproc-1", stop))
        yield
        if task is not None:
            stop.set()
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

    dev = settings.env != "prod"
    app = FastAPI(title="SafeTrace API", version="0.1.0", lifespan=lifespan,
                  docs_url="/docs" if dev else None, redoc_url=None, openapi_url="/openapi.json" if dev else None)
    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_methods=["GET", "POST"],
                       allow_headers=["Authorization", "Content-Type", "Last-Event-ID"], allow_credentials=False)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            resp.headers.setdefault(k, v)
        return resp

    @app.exception_handler(OrchestratorError)
    async def orch_error(_: Request, exc: OrchestratorError) -> JSONResponse:
        return JSONResponse({"error": exc.code}, status_code=exc.http_status)

    if settings.labeling_enabled:
        from safetrace.api.labeling import build_router, labeling_error_response
        from safetrace.labeling.store import LabelingError, LabelStore

        app.add_exception_handler(LabelingError, lambda _, exc: labeling_error_response(exc))
        app.include_router(build_router(LabelStore(settings.d1r_dir, settings.labeling_sample_rate,
                                                   settings.labeling_salt, settings.labeling_labelers)))

    @app.exception_handler(Exception)
    async def unhandled(_: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error")  # 상세는 서버 로그에만
        return JSONResponse({"error": "INTERNAL_ERROR"}, status_code=500)

    def orch(request: Request) -> Orchestrator:
        return request.app.state.orch

    Orch = Annotated[Orchestrator, Depends(orch)]

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    # ───────────── 콘솔 API ─────────────

    @app.get("/api/me")
    def me(p: Annotated[Principal, Depends(require(*ANY))]) -> dict[str, str]:
        return {"user_id": p.user_id, "role": p.role.value}

    @app.post("/api/cases", status_code=201)
    async def submit(body: SubmitUrl, o: Orch, p: Annotated[Principal, Depends(require(*SUBMITTERS))]):
        if body.source not in (SeedSource.REPORT, SeedSource.KISA, SeedSource.SEARCH_API):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid source")
        cand = await o.submit(str(body.url), body.source, f"{p.role.value}:{p.user_id}")
        return {"case_id": cand.case_id, "candidate_id": cand.candidate_id, "normalized_url": cand.normalized_url}

    @app.post("/api/seeds/kisa")
    async def kisa_seed(request: Request, o: Orch, p: Annotated[Principal, Depends(require(*SUBMITTERS))],
                        limit: Annotated[int, Query(ge=1, le=200)] = 20):
        res = load_csv(await read_limited(request, MAX_CSV))
        submitted = []
        for rec in res.records[:limit]:
            try:
                cand = await o.submit(rec.normalized_url, SeedSource.KISA, f"{p.role.value}:{p.user_id}")
                submitted.append(cand.candidate_id)
            except OrchestratorError:
                continue
        return {"loaded": len(res.records), "rejected": len(res.rejected), "duplicates": res.duplicates,
                "submitted": len(submitted)}

    @app.get("/api/stats")
    def stats(o: Orch, _: Annotated[Principal, Depends(require(*ANY))]):
        return o.stats()

    @app.get("/api/candidates")
    def list_candidates(o: Orch, _: Annotated[Principal, Depends(require(*ANY))]):
        out = []
        for c in sorted(o.candidates.values(), key=lambda c: c.created_at, reverse=True)[:500]:
            a = o.analyses.get(c.candidate_id)
            out.append({
                "candidate_id": c.candidate_id, "case_id": c.case_id, "url": c.normalized_url,
                "source": c.source, "status": c.status, "status_reason": c.status_reason,
                "priority": c.priority, "depth": c.depth, "discovered_from": c.discovered_from,
                "relation": c.relation, "created_at": c.created_at,
                "ai_state": a.state if a else None,
                "ai_top": ({"type": a.threat_types[0].type, "confidence": a.threat_types[0].confidence}
                           if a and a.threat_types else None),
            })
        return out

    @app.get("/api/candidates/{candidate_id}")
    async def candidate_detail(candidate_id: str, o: Orch, _: Annotated[Principal, Depends(require(*ANY))]):
        c = o.candidates.get(candidate_id)
        if c is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        evidence = await o.ledger.list_for_candidate(candidate_id)
        return {
            "candidate": c.model_dump(mode="json"),
            "observation": o.observations[candidate_id].model_dump(mode="json")
            if candidate_id in o.observations else None,
            "analysis": o.analyses[candidate_id].model_dump(mode="json") if candidate_id in o.analyses else None,
            "reputation": [r.model_dump(mode="json") for r in o.reputations.get(candidate_id, [])],
            "review": o.reviews[candidate_id].model_dump(mode="json") if candidate_id in o.reviews else None,
            "evidence": [e.model_dump(mode="json") for e in evidence],
            "impersonates": o.impersonates.get(candidate_id, []),
        }

    @app.get("/api/candidates/{candidate_id}/package")
    async def package(candidate_id: str, o: Orch, p: Annotated[Principal, Depends(require(*ANY))]):
        pkg = await o.package(candidate_id)
        o.record_audit(f"{p.role.value}:{p.user_id}", "package.export", candidate_id)
        return pkg

    @app.post("/api/candidates/{candidate_id}/review")
    def review(candidate_id: str, body: ReviewIn, o: Orch, p: Annotated[Principal, Depends(require(*ANY))]):
        r = o.decide(candidate_id, f"{p.role.value}:{p.user_id}", p.role.value, body.decision, body.reason)
        return r.model_dump(mode="json")

    @app.get("/api/evidence/verify")
    async def verify_chain(o: Orch, _: Annotated[Principal, Depends(require(*ANY))]):
        return (await o.ledger.verify()).model_dump(mode="json")

    @app.get("/api/evidence/{evidence_id}/content")
    async def evidence_content(evidence_id: str, o: Orch, p: Annotated[Principal, Depends(require(*ANY))]):
        ev = await o.ledger.get(evidence_id)
        if ev is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        try:
            data = await asyncio.to_thread(o.ledger.read_object, ev)
        except (FileNotFoundError, ValueError):
            raise HTTPException(status.HTTP_410_GONE, "evidence object missing") from None
        if sha256_bytes(data) != ev.sha256:  # 조회 시 재검증
            o.record_audit(f"{p.role.value}:{p.user_id}", "evidence.read", evidence_id, "ERROR", "HASH_MISMATCH")
            raise HTTPException(status.HTTP_409_CONFLICT, "EVIDENCE_TAMPERED")
        ctype, disp = CONTENT_TYPES[ev.type]
        return Response(data, media_type=ctype, headers={
            "Content-Disposition": f'{disp}; filename="{ev.evidence_id}"', "X-Evidence-SHA256": ev.sha256,
        })

    @app.get("/api/graph")
    def graph(o: Orch, _: Annotated[Principal, Depends(require(*ANY))]):
        nodes = [{"id": c.candidate_id, "url": c.normalized_url, "status": c.status, "depth": c.depth,
                  "kind": "candidate"} for c in o.candidates.values()]
        kinds = {"IMPERSONATES": ("impersonated", "ALLOWLISTED"), "TRAVERSED": ("traversed", "TRAVERSED")}
        extra = {e["to"]: kinds[e["relation"]] for e in o.edges if e["relation"] in kinds}
        nodes += [{"id": t, "url": t, "status": st, "depth": None, "kind": k} for t, (k, st) in extra.items()]
        return {"nodes": nodes, "edges": o.edges}

    @app.get("/api/audit")
    def audit(o: Orch, _: Annotated[Principal, Depends(require(Role.REVIEWER))]):
        return [a.model_dump(mode="json") for a in o.audit[-500:]]

    @app.get("/api/events")
    async def events(request: Request, o: Orch, _: Annotated[Principal, Depends(require(*ANY))],
                     last_event_id: Annotated[str, Header(alias="Last-Event-ID")] = "0"):
        start = int(last_event_id) if last_event_id.isdigit() else 0

        async def stream() -> AsyncIterator[bytes]:
            async with o.bus.subscribe(start) as q:
                yield b"retry: 3000\n\n"
                snapshot = json.dumps({"type": "pipeline.stats", "data": o.stats()})
                yield f"event: pipeline.stats\ndata: {snapshot}\n\n".encode()
                while not await request.is_disconnected():
                    try:
                        ev = await asyncio.wait_for(q.get(), 15)
                    except TimeoutError:
                        if not o.bus.is_subscribed(q):
                            break
                        yield b": keepalive\n\n"
                        continue
                    payload = ev.model_dump_json()
                    yield f"id: {ev.event_id}\nevent: {ev.type}\ndata: {payload}\n\n".encode()

        return StreamingResponse(stream(), media_type="text/event-stream",
                                 headers={"X-Accel-Buffering": "no", "Cache-Control": "no-store"})

    # ───────────── Worker 전용 수집 API ─────────────

    def worker_auth(authorization: Annotated[str, Header()] = "",
                    x_worker_id: Annotated[str, Header()] = "") -> str:
        if not worker_token or not hmac.compare_digest(authorization.encode(), f"Bearer {worker_token}".encode()):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unauthorized")
        if not x_worker_id or len(x_worker_id) > 64 or not x_worker_id.replace("-", "").replace("_", "").isalnum():
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "bad worker id")
        return x_worker_id

    Worker = Annotated[str, Depends(worker_auth)]
    staged: dict[str, dict[EvidenceType, bytes]] = {}

    @app.post("/ingest/v1/lease")
    async def lease(o: Orch, wid: Worker):
        job = await o.lease(wid)
        if job is None:
            return Response(status_code=204)
        staged[job["job_id"]] = {}
        return job

    @app.post("/ingest/v1/jobs/{job_id}/frame", status_code=204)
    async def frame(job_id: str, request: Request, o: Orch, wid: Worker):
        o.push_frame(job_id, wid, await read_limited(request, 400_000))

    @app.post("/ingest/v1/jobs/{job_id}/step", status_code=204)
    def step(job_id: str, body: StepIn, o: Orch, wid: Worker):
        o.push_step(job_id, wid, body.step, body.data)

    @app.post("/ingest/v1/jobs/{job_id}/artifact/{etype}", status_code=204)
    async def artifact(job_id: str, etype: EvidenceType, request: Request, o: Orch, wid: Worker):
        o._take_lease(job_id, wid)
        from safetrace.pipeline.orchestrator import MAX_ARTIFACT_BYTES

        staged.setdefault(job_id, {})[etype] = await read_limited(request, MAX_ARTIFACT_BYTES[etype])

    @app.post("/ingest/v1/jobs/{job_id}/result", status_code=204)
    async def result(job_id: str, request: Request, o: Orch, wid: Worker):
        obs = Observation.model_validate_json(await read_limited(request, MAX_JSON))
        await o.complete(job_id, wid, obs, staged.pop(job_id, {}))

    @app.post("/ingest/v1/jobs/{job_id}/fail", status_code=204)
    def fail(job_id: str, body: FailIn, o: Orch, wid: Worker):
        staged.pop(job_id, None)
        o.fail(job_id, wid, body.code)

    return app


def main() -> None:
    import os

    import uvicorn

    logging.basicConfig(level=logging.INFO)
    uvicorn.run(create_app(), host=os.environ.get("SAFETRACE_API_HOST", "127.0.0.1"),
                port=int(os.environ.get("SAFETRACE_API_PORT", "8000")), server_header=False)


if __name__ == "__main__":
    main()
