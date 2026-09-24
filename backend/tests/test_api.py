"""API 보안 통제: 인증·RBAC(R7 자동화 계정 판정 차단)·수집 API 분리·증거 조회 재검증·보안 헤더."""

import asyncio

import httpx
import pytest

from safetrace.ai.engine import DecisionEngine
from safetrace.api.app import create_app
from safetrace.api.auth import TokenRegistry, token_hash
from safetrace.config import Settings
from safetrace.pipeline.events import EventBus
from safetrace.pipeline.orchestrator import Orchestrator
from safetrace.reputation.safebrowsing import SafeBrowsingClient
from safetrace.schemas import CandidateStatus, EvidenceType, Observation
from safetrace.security.url_policy import UrlPolicy

TOKENS = {"viewer-token": "vic:viewer", "inv-token": "ian:investigator", "rev-token": "rita:reviewer",
          "bot-token": "bot:automation"}
WORKER_TOKEN = "w" * 32


def H(tok: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {tok}"}


@pytest.fixture
async def env(ledger, site):
    orch = Orchestrator(ledger=ledger, engine=DecisionEngine(), bus=EventBus(),
                        policy=UrlPolicy(allow_hostports=frozenset({site})), safebrowsing=SafeBrowsingClient(""))
    reg = TokenRegistry({token_hash(t): spec for t, spec in TOKENS.items()})
    app = create_app(Settings(env="test", worker_token=WORKER_TOKEN), orchestrator=orch, registry=reg,
                     inproc_worker=False)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://api") as c:
            yield c, orch


async def _wait_status(orch, cid, status, wait_s=5.0):
    for _ in range(int(wait_s / 0.05)):
        if orch.candidates[cid].status == status:
            return
        await asyncio.sleep(0.05)
    raise AssertionError(f"{orch.candidates[cid].status} != {status}")


async def _run_job(c, orch, site, path="/phish"):
    r = await c.post("/api/cases", json={"url": f"http://{site}{path}"}, headers=H("inv-token"))
    assert r.status_code == 201
    cid = r.json()["candidate_id"]
    await _wait_status(orch, cid, CandidateStatus.QUEUED)
    wh = {**H(WORKER_TOKEN), "X-Worker-Id": "w1"}
    job = (await c.post("/ingest/v1/lease", json={"worker_id": "w1"}, headers=wh)).json()
    from safetrace.agent.extract import extract

    from .test_ai_engine import PHISH_RENDERED

    s, forms, links, _ = extract(PHISH_RENDERED, f"http://{site}{path}")
    obs = Observation(candidate_id=cid, requested_url=f"http://{site}{path}", final_url=f"http://{site}{path}",
                      dom_summary=s, forms=forms, observed_links=links)
    assert (await c.post(f"/ingest/v1/jobs/{job['job_id']}/artifact/SCREENSHOT", content=b"\x89PNG fake",
                         headers=wh)).status_code == 204
    assert (await c.post(f"/ingest/v1/jobs/{job['job_id']}/result", content=obs.model_dump_json(),
                         headers={**wh, "Content-Type": "application/json"})).status_code == 204
    return cid


async def test_auth_required_and_security_headers(env):
    c, _ = env
    r = await c.get("/api/stats")
    assert r.status_code == 401
    r = await c.get("/api/stats", headers=H("viewer-token"))
    assert r.status_code == 200
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]


async def test_viewer_cannot_submit(env):
    c, _ = env
    r = await c.post("/api/cases", json={"url": "http://example.com/"}, headers=H("viewer-token"))
    assert r.status_code == 403


async def test_invalid_url_rejected_without_leaking(env):
    c, _ = env
    r = await c.post("/api/cases", json={"url": "http://user:pw@example.com/"}, headers=H("inv-token"))
    assert r.status_code in (400, 422)


async def test_private_seed_blocked_at_screening(env):
    c, orch = env
    r = await c.post("/api/cases", json={"url": "http://169.254.169.254/latest/"}, headers=H("inv-token"))
    cid = r.json()["candidate_id"]
    await _wait_status(orch, cid, CandidateStatus.BLOCKED)
    assert orch.candidates[cid].status_reason == "IP_NOT_PUBLIC"


async def test_ingest_requires_worker_token(env):
    c, _ = env
    assert (await c.post("/ingest/v1/lease", json={"worker_id": "w1"}, headers=H("rev-token"))).status_code == 401
    assert (await c.post("/ingest/v1/lease", json={"worker_id": "w1"},
                         headers={**H(WORKER_TOKEN), "X-Worker-Id": "../x"})).status_code == 400


async def test_full_flow_review_rbac(env, site):
    c, orch = env
    cid = await _run_job(c, orch, site)
    assert orch.candidates[cid].status == CandidateStatus.REVIEW_REQUIRED
    detail = (await c.get(f"/api/candidates/{cid}", headers=H("viewer-token"))).json()
    assert detail["analysis"]["threat_types"][0]["type"] == "PHISHING"
    assert {e["type"] for e in detail["evidence"]} == {"SCREENSHOT", "OBSERVATION"}

    body = {"decision": "THREAT_CONFIRMED", "reason": "사칭 문구와 외부 전송 폼 확인"}
    for tok in ("bot-token", "inv-token", "viewer-token"):  # R7: 자동화·조사자·열람자는 판정 불가
        assert (await c.post(f"/api/candidates/{cid}/review", json=body, headers=H(tok))).status_code == 403
    assert any(a.result == "DENIED" and a.actor == "automation:bot" for a in orch.audit)
    r = await c.post(f"/api/candidates/{cid}/review", json=body, headers=H("rev-token"))
    assert r.status_code == 200
    assert orch.candidates[cid].status == CandidateStatus.DECIDED

    pkg = (await c.get(f"/api/candidates/{cid}/package", headers=H("viewer-token"))).json()
    assert pkg["evidence"]["integrity"]["ok"] is True
    assert pkg["reviewer_area"]["decision"] == "THREAT_CONFIRMED"
    assert pkg["ai_analysis"]["decision_authority"] == "NONE"


async def test_evidence_content_reverified_on_read(env, site):
    c, orch = env
    cid = await _run_job(c, orch, site)
    evs = await orch.ledger.list_for_candidate(cid)
    shot = next(e for e in evs if e.type == EvidenceType.SCREENSHOT)
    html_ev = next(e for e in evs if e.type == EvidenceType.OBSERVATION)
    r = await c.get(f"/api/evidence/{shot.evidence_id}/content", headers=H("viewer-token"))
    assert r.status_code == 200 and r.headers["content-type"] == "image/png"
    r = await c.get(f"/api/evidence/{html_ev.evidence_id}/content", headers=H("viewer-token"))
    assert r.headers["content-disposition"].startswith("attachment")
    (orch.ledger.root / shot.object_path).write_bytes(b"tampered")
    r = await c.get(f"/api/evidence/{shot.evidence_id}/content", headers=H("viewer-token"))
    assert r.status_code == 409
    v = (await c.get("/api/evidence/verify", headers=H("viewer-token"))).json()
    assert v["ok"] is False


async def test_event_bus_replay_and_stats(env, site):
    c, orch = env
    await _run_job(c, orch, site)
    async with orch.bus.subscribe(0) as q:
        types = []
        while not q.empty():
            types.append((await q.get()).type)
    for t in ("candidate.discovered", "candidate.status", "evidence.stored", "analysis.done",
              "reputation.done", "discovery.expanded", "pipeline.stats"):
        assert t in types
    stats = (await c.get("/api/stats", headers=H("viewer-token"))).json()
    assert stats["review_required"] == 1 and stats["discovered"] >= 2  # 관찰 링크로 후속 후보 발굴
