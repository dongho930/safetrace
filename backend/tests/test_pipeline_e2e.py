"""사전준비 종단 시험: Seed 1건 → 후보 큐 → 격리 조사(실제 Chromium) → 증거 저장 → AI → 재큐잉 → 검토 대기."""

import asyncio

import pytest

from safetrace.agent.browser import AgentLimits, BrowserAgent
from safetrace.ai.engine import DecisionEngine
from safetrace.pipeline.events import EventBus
from safetrace.pipeline.orchestrator import Orchestrator
from safetrace.reputation.safebrowsing import SafeBrowsingClient
from safetrace.schemas import CandidateStatus, SeedSource, ThreatType
from safetrace.security.url_policy import UrlPolicy
from safetrace.worker.main import LocalJobSource, run_worker

pytestmark = pytest.mark.browser


async def test_seed_to_review_with_requeue(ledger, site):
    policy = UrlPolicy(allow_hostports=frozenset({site}))
    orch = Orchestrator(ledger=ledger, engine=DecisionEngine(), bus=EventBus(), policy=policy,
                        safebrowsing=SafeBrowsingClient(""))
    agent = BrowserAgent(policy, AgentLimits(page_timeout_s=10, settle_s=1.2, total_budget_s=40),
                         record_video=False)
    stop = asyncio.Event()
    worker = asyncio.create_task(run_worker(LocalJobSource(orch), agent, "w-test", stop))
    try:
        seed = await orch.submit(f"http://{site}/phish", SeedSource.KISA, "tester")
        for _ in range(600):
            done = [c for c in orch.candidates.values() if c.status == CandidateStatus.REVIEW_REQUIRED]
            if seed.status == CandidateStatus.REVIEW_REQUIRED and len(done) >= 2:
                break
            await asyncio.sleep(0.1)
    finally:
        stop.set()
        worker.cancel()

    assert seed.status == CandidateStatus.REVIEW_REQUIRED
    a = orch.analyses[seed.candidate_id]
    assert a.threat_types[0].type == ThreatType.PHISHING
    # 허용목록(nhis.or.kr)은 재큐잉되지 않고 사칭 대상으로만 기록
    assert "nhis.or.kr" in orch.impersonates[seed.candidate_id]
    assert not any("nhis.or.kr" in c.normalized_url for c in orch.candidates.values())
    children = [c for c in orch.candidates.values() if c.discovered_from == seed.candidate_id]
    assert any(c.normalized_url.endswith("/child-a") for c in children)
    assert all(c.depth == 1 for c in children)
    # 증거 체인 무결성
    v = await ledger.verify()
    assert v.ok and v.checked >= 3
