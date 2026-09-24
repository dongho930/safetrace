"""조사 Worker. 격리망에서 실행되며 수집 API(작업 임대·결과 전달)와 egress 프록시에만 접근한다.

Worker 는 DB·큐·서명 자격증명을 갖지 않는다. 가진 것은 Worker 토큰과 프록시 주소뿐이다.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Protocol

import httpx

from safetrace.config import Settings, get_settings
from safetrace.schemas import EvidenceType, Observation
from safetrace.security.url_policy import UrlPolicy

log = logging.getLogger("safetrace.worker")


class JobSource(Protocol):
    async def lease(self, worker_id: str) -> dict[str, Any] | None: ...
    async def frame(self, job_id: str, worker_id: str, jpeg: bytes) -> None: ...
    async def step(self, job_id: str, worker_id: str, step: str, data: dict) -> None: ...
    async def complete(self, job_id: str, worker_id: str, obs: Observation,
                       artifacts: dict[EvidenceType, bytes]) -> None: ...
    async def fail(self, job_id: str, worker_id: str, code: str) -> None: ...


class HttpJobSource:
    """격리 Worker → ingest-gw → API(/ingest/*)."""

    def __init__(self, base_url: str, token: str, worker_id: str) -> None:
        self._c = httpx.AsyncClient(base_url=base_url, timeout=httpx.Timeout(60.0),
                                    headers={"Authorization": f"Bearer {token}", "X-Worker-Id": worker_id},
                                    trust_env=False)  # 수집 API 호출은 egress 프록시를 타지 않는다

    async def lease(self, worker_id: str) -> dict[str, Any] | None:
        r = await self._c.post("/ingest/v1/lease", json={"worker_id": worker_id})
        if r.status_code == 204:
            return None
        r.raise_for_status()
        return r.json()

    async def frame(self, job_id: str, worker_id: str, jpeg: bytes) -> None:
        await self._c.post(f"/ingest/v1/jobs/{job_id}/frame", content=jpeg,
                           headers={"Content-Type": "image/jpeg"})

    async def step(self, job_id: str, worker_id: str, step: str, data: dict) -> None:
        await self._c.post(f"/ingest/v1/jobs/{job_id}/step", json={"step": step, "data": data})

    async def complete(self, job_id: str, worker_id: str, obs: Observation,
                       artifacts: dict[EvidenceType, bytes]) -> None:
        for et, data in artifacts.items():
            if et == EvidenceType.OBSERVATION:
                continue
            r = await self._c.post(f"/ingest/v1/jobs/{job_id}/artifact/{et.value}", content=data,
                                   headers={"Content-Type": "application/octet-stream"})
            r.raise_for_status()
        r = await self._c.post(f"/ingest/v1/jobs/{job_id}/result", content=obs.model_dump_json(),
                               headers={"Content-Type": "application/json"})
        r.raise_for_status()

    async def fail(self, job_id: str, worker_id: str, code: str) -> None:
        await self._c.post(f"/ingest/v1/jobs/{job_id}/fail", json={"code": code})


class LocalJobSource:
    """개발용: 같은 프로세스의 오케스트레이터에 직접 연결(격리 없음 — 로컬 시험 페이지 전용)."""

    def __init__(self, orch) -> None:
        self.o = orch

    async def lease(self, worker_id: str) -> dict[str, Any] | None:
        return await self.o.lease(worker_id, wait_s=5)

    async def frame(self, job_id: str, worker_id: str, jpeg: bytes) -> None:
        self.o.push_frame(job_id, worker_id, jpeg)

    async def step(self, job_id: str, worker_id: str, step: str, data: dict) -> None:
        self.o.push_step(job_id, worker_id, step, data)

    async def complete(self, job_id: str, worker_id: str, obs: Observation,
                       artifacts: dict[EvidenceType, bytes]) -> None:
        await self.o.complete(job_id, worker_id, obs, artifacts)

    async def fail(self, job_id: str, worker_id: str, code: str) -> None:
        self.o.fail(job_id, worker_id, code)


def make_agent(settings: Settings, local: bool = False):
    from safetrace.agent.browser import AgentLimits, BrowserAgent

    policy = UrlPolicy(allow_hostports=settings.allowed_test_hostports(),
                       resolve_dns=local or not settings.egress_proxy)
    limits = AgentLimits(page_timeout_s=settings.page_timeout_s, max_requests=settings.max_requests_per_page,
                         max_redirects=settings.max_redirects, max_html_bytes=settings.max_html_bytes,
                         total_budget_s=min(settings.case_time_budget_s, 120))
    return BrowserAgent(policy, limits, proxy=settings.egress_proxy,
                        chromium_sandbox=os.environ.get("SAFETRACE_CHROMIUM_SANDBOX") == "1",
                        egress_deny_token=settings.egress_deny_token.get_secret_value())


async def run_worker(source: JobSource, agent, worker_id: str, stop: asyncio.Event) -> None:
    while not stop.is_set():
        try:
            job = await source.lease(worker_id)
        except (httpx.HTTPError, OSError) as exc:
            log.warning("lease failed: %s", type(exc).__name__)
            await asyncio.sleep(3)
            continue
        if job is None:
            continue
        job_id, cid, url = job["job_id"], job["candidate_id"], job["url"]

        async def on_frame(jpeg: bytes, _job=job_id) -> None:
            await source.frame(_job, worker_id, jpeg)

        async def on_step(step: str, data: dict, _job=job_id) -> None:
            await source.step(_job, worker_id, step, data)

        try:
            result = await agent.investigate(cid, url, on_frame=on_frame, on_step=on_step)
            await source.complete(job_id, worker_id, result.observation, result.artifacts)
        except Exception as exc:  # noqa: BLE001 - 한 건의 실패가 Worker 를 멈추지 않게
            log.exception("job %s failed", job_id)
            try:
                await source.fail(job_id, worker_id, type(exc).__name__.upper()[:64])
            except Exception:  # noqa: BLE001
                log.warning("fail report failed")


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    settings = get_settings()
    worker_id = os.environ.get("SAFETRACE_WORKER_ID", "worker-1")
    ingest = os.environ.get("SAFETRACE_INGEST_URL", "http://ingest-gw:8080")
    source = HttpJobSource(ingest, settings.worker_token.get_secret_value(), worker_id)
    asyncio.run(run_worker(source, make_agent(settings), worker_id, asyncio.Event()))


if __name__ == "__main__":
    main()
