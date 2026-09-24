"""Google Safe Browsing Lookup API(v4 threatMatches:find) 조회 — 외부 평판 보조 신호.

- 미등재(NOT_LISTED)는 BENIGN 근거로 쓰지 않는다.
- 키 미설정은 SKIPPED, 장애·쿼터 초과는 ERROR 로 기록하고 핵심 흐름은 계속 진행한다.
- API 키는 쿼리 파라미터로 전달되므로 요청 URL 을 로그에 남기지 않는다.
"""

from __future__ import annotations

import asyncio
import time

import httpx

from safetrace.schemas import Reputation, ReputationResult

ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]
PROVIDER = "google_safe_browsing_v4"


class SafeBrowsingClient:
    def __init__(self, api_key: str, transport: httpx.AsyncBaseTransport | None = None,
                 min_interval_s: float = 0.2, timeout_s: float = 5.0) -> None:
        self._key = api_key
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(timeout_s), transport=transport)
        self._min_interval = min_interval_s
        self._last = 0.0
        self._lock = asyncio.Lock()

    async def lookup(self, urls: list[str]) -> list[Reputation]:
        urls = list(dict.fromkeys(u for u in urls if u))[:500]
        if not self._key:
            return [Reputation(provider=PROVIDER, url=u, result=ReputationResult.SKIPPED,
                               detail="API key not configured") for u in urls]
        body = {
            "client": {"clientId": "safetrace", "clientVersion": "0.1.0"},
            "threatInfo": {
                "threatTypes": THREAT_TYPES,
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in urls],
            },
        }
        async with self._lock:  # 호출 간격 제한(쿼터 보호)
            wait = self._min_interval - (time.monotonic() - self._last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()
            try:
                r = await self._client.post(ENDPOINT, params={"key": self._key}, json=body)
            except httpx.HTTPError as exc:
                return self._errors(urls, type(exc).__name__)
        if r.status_code != 200:
            return self._errors(urls, f"HTTP {r.status_code}")
        try:
            matches = r.json().get("matches", [])
        except ValueError:
            return self._errors(urls, "invalid JSON")
        hits: dict[str, list[str]] = {}
        for m in matches:
            url = m.get("threat", {}).get("url", "")
            hits.setdefault(url, []).append(str(m.get("threatType", "UNKNOWN"))[:64])
        return [
            Reputation(provider=PROVIDER, url=u, result=ReputationResult.LISTED, threats=sorted(set(hits[u])))
            if u in hits else
            Reputation(provider=PROVIDER, url=u, result=ReputationResult.NOT_LISTED,
                       detail="미등재는 정상 근거가 아님")
            for u in urls
        ]

    @staticmethod
    def _errors(urls: list[str], detail: str) -> list[Reputation]:
        return [Reputation(provider=PROVIDER, url=u, result=ReputationResult.ERROR, detail=detail) for u in urls]

    async def aclose(self) -> None:
        await self._client.aclose()
