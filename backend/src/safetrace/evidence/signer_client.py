"""서명 서비스 HTTP 클라이언트. API 프로세스는 키 대신 서비스 토큰만 가진다."""

from __future__ import annotations

import httpx


class SignerError(Exception):
    pass


class SignerClient:
    def __init__(self, base_url: str, token: str, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=httpx.Timeout(5.0),
            transport=transport,
        )

    async def sign(self, seq: int, record_hash: str) -> tuple[str, str]:
        r = await self._client.post("/v1/sign", json={"seq": seq, "record_hash": record_hash})
        if r.status_code != 200:
            raise SignerError(f"sign failed: HTTP {r.status_code}")
        data = r.json()
        return str(data["sig"]), str(data["key_id"])

    async def verify(self, seq: int, record_hash: str, sig: str, key_id: str) -> bool:
        r = await self._client.post(
            "/v1/verify", json={"seq": seq, "record_hash": record_hash, "sig": sig, "key_id": key_id}
        )
        if r.status_code != 200:
            # 형식 오류(변조된 서명 문자열 등)도 검증 실패로 취급한다.
            return False
        return bool(r.json()["valid"])

    async def head(self) -> tuple[int, str]:
        r = await self._client.get("/v1/head")
        if r.status_code != 200:
            raise SignerError(f"head failed: HTTP {r.status_code}")
        data = r.json()
        return int(data["max_seq"]), str(data["head_hash"])

    async def aclose(self) -> None:
        await self._client.aclose()
