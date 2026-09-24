"""분리 서명 서비스. HMAC 키는 이 프로세스(컨테이너)에만 존재한다.

증거 저장소·DB 권한만으로는 유효한 서명을 만들 수 없게 하는 것이 목적이다(기획서 2.7 증거 무결성).
또한 서명한 최대 seq(high-water mark)를 자체 저장소에 기록해, 체인 끝 레코드 삭제(tail truncation)도 탐지한다.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

DOMAIN = "safetrace.evidence.v1"
HexHash = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class SignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    seq: int = Field(ge=1)
    record_hash: HexHash


class SignResponse(BaseModel):
    sig: str
    key_id: str


class VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    seq: int = Field(ge=1)
    record_hash: HexHash
    sig: HexHash
    key_id: Annotated[str, Field(max_length=64)]


class VerifyResponse(BaseModel):
    valid: bool


class HeadResponse(BaseModel):
    max_seq: int
    head_hash: str


class SignerCore:
    def __init__(self, key: bytes, state_path: Path) -> None:
        if len(key) < 32:
            raise ValueError("서명 키는 32바이트 이상이어야 한다")
        self._key = key
        self.key_id = "k-" + hashlib.sha256(b"key-id|" + key).hexdigest()[:12]
        self._state_path = state_path
        self._lock = threading.Lock()
        self._max_seq, self._head = self._load_state()

    def _load_state(self) -> tuple[int, str]:
        if not self._state_path.exists():
            return 0, ""
        data = json.loads(self._state_path.read_text(encoding="utf-8"))
        return int(data["max_seq"]), str(data["head_hash"])

    def _save_state(self) -> None:
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"max_seq": self._max_seq, "head_hash": self._head}), encoding="utf-8")
        os.replace(tmp, self._state_path)

    def _mac(self, seq: int, record_hash: str) -> str:
        return hmac.new(self._key, f"{DOMAIN}|{seq}|{record_hash}".encode(), hashlib.sha256).hexdigest()

    def sign(self, seq: int, record_hash: str) -> str:
        with self._lock:
            # 추가 전용: 이미 서명한 seq 이하를 다른 해시로 다시 서명하지 않는다(체인 재작성 방지).
            if seq <= self._max_seq:
                raise PermissionError("seq already signed")
            if seq != self._max_seq + 1:
                raise PermissionError("seq gap")
            sig = self._mac(seq, record_hash)
            self._max_seq, self._head = seq, record_hash
            self._save_state()
            return sig

    def verify(self, seq: int, record_hash: str, sig: str, key_id: str) -> bool:
        if not hmac.compare_digest(key_id, self.key_id):
            return False
        return hmac.compare_digest(self._mac(seq, record_hash), sig)

    def head(self) -> tuple[int, str]:
        return self._max_seq, self._head


def create_app(core: SignerCore, token: str) -> FastAPI:
    if len(token) < 24:
        raise ValueError("서비스 토큰은 24자 이상이어야 한다")
    app = FastAPI(title="SafeTrace Signer", docs_url=None, redoc_url=None, openapi_url=None)

    def auth(authorization: Annotated[str, Header()] = "") -> None:
        expected = f"Bearer {token}"
        if not hmac.compare_digest(authorization.encode(), expected.encode()):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unauthorized")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/sign", dependencies=[Depends(auth)])
    def sign(req: SignRequest) -> SignResponse:
        try:
            return SignResponse(sig=core.sign(req.seq, req.record_hash), key_id=core.key_id)
        except PermissionError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None

    @app.post("/v1/verify", dependencies=[Depends(auth)])
    def verify(req: VerifyRequest) -> VerifyResponse:
        return VerifyResponse(valid=core.verify(req.seq, req.record_hash, req.sig, req.key_id))

    @app.get("/v1/head", dependencies=[Depends(auth)])
    def head() -> HeadResponse:
        max_seq, head_hash = core.head()
        return HeadResponse(max_seq=max_seq, head_hash=head_hash)

    return app


def _load_key() -> bytes:
    key_file = os.environ.get("SAFETRACE_SIGNER_KEY_FILE")
    if key_file:
        return bytes.fromhex(Path(key_file).read_text(encoding="utf-8").strip())
    key_hex = os.environ.get("SAFETRACE_SIGNER_KEY", "")
    if not key_hex:
        raise SystemExit("SAFETRACE_SIGNER_KEY 또는 SAFETRACE_SIGNER_KEY_FILE 이 필요하다")
    return bytes.fromhex(key_hex)


def main() -> None:
    import uvicorn

    core = SignerCore(_load_key(), Path(os.environ.get("SAFETRACE_SIGNER_STATE", "./var/signer/state.json")))
    token = os.environ.get("SAFETRACE_SIGNER_TOKEN", "")
    host = os.environ.get("SAFETRACE_SIGNER_HOST", "127.0.0.1")
    uvicorn.run(create_app(core, token), host=host, port=int(os.environ.get("SAFETRACE_SIGNER_PORT", "8081")))


if __name__ == "__main__":
    main()
