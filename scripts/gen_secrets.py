"""개발 환경 비밀값 생성: .env(토큰 해시·서비스 토큰)와 secrets/signer_key.hex.

토큰 원문은 이 실행에서 한 번만 화면에 출력되고 저장되지 않는다(.env 에는 SHA-256 해시만 기록).
이미 파일이 있으면 덮어쓰지 않는다(--force 로 재생성).
"""

import hashlib
import json
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV = ROOT / ".env"
KEY = ROOT / "secrets" / "signer_key.hex"
USERS = [("admin", "reviewer"), ("investigator", "investigator"), ("viewer", "viewer"), ("bot", "automation")]


def main() -> None:
    force = "--force" in sys.argv
    if (ENV.exists() or KEY.exists()) and not force:
        raise SystemExit(".env 또는 secrets/ 가 이미 있다. 재생성하려면 --force")
    tokens = {u: secrets.token_urlsafe(32) for u, _ in USERS}
    mapping = {hashlib.sha256(tokens[u].encode()).hexdigest(): f"{u}:{r}" for u, r in USERS}
    KEY.parent.mkdir(exist_ok=True)
    KEY.write_text(secrets.token_hex(32), encoding="utf-8")
    ENV.write_text("\n".join([
        "SAFETRACE_ENV=dev",
        f"SAFETRACE_API_TOKENS={json.dumps(mapping)}",
        f"SAFETRACE_SIGNER_TOKEN={secrets.token_urlsafe(32)}",
        f"SAFETRACE_WORKER_TOKEN={secrets.token_urlsafe(32)}",
        f"SAFETRACE_DB_PASSWORD={secrets.token_urlsafe(24)}",
        f"SAFETRACE_REDIS_PASSWORD={secrets.token_urlsafe(24)}",
        "SAFETRACE_SAFE_BROWSING_API_KEY=",
        "# 로컬 개발(도커 없이) 전용: 서명 키를 직접 전달",
        f"SAFETRACE_SIGNER_KEY_FILE={KEY.as_posix()}",
        "",
    ]), encoding="utf-8")
    print("생성 완료: .env, secrets/signer_key.hex")
    print("콘솔 로그인 토큰(다시 표시되지 않음):")
    for u, r in USERS:
        print(f"  {u:<13} ({r:<12}) {tokens[u]}")


if __name__ == "__main__":
    main()
