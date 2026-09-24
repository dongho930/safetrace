"""개발 환경 비밀값 생성: .env(토큰 해시·서비스 토큰)와 secrets/signer_key.hex.

토큰 원문은 이 실행에서 한 번만 화면에 출력되고 저장되지 않는다(.env 에는 SHA-256 해시만 기록).
이미 파일이 있으면 덮어쓰지 않는다(--force 로 재생성).
--add-missing: 기존 .env 는 그대로 두고, 이후 추가된 서비스 비밀값(아래 LATER_SECRETS)만 덧붙인다.
"""

import hashlib
import json
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV = ROOT / ".env"
KEY = ROOT / "secrets" / "signer_key.hex"
# 최초 생성 이후에 추가된 서비스 간 비밀값. 기존 .env 에 없으면 --add-missing 으로 덧붙인다.
LATER_SECRETS = {"SAFETRACE_EGRESS_DENY_TOKEN": "egress 프록시 거부 응답 확인용(프록시·Worker·수집기 공유)"}
USERS = [("admin", "reviewer"), ("investigator", "investigator"), ("viewer", "viewer"), ("bot", "automation")]


def add_missing() -> None:
    if not ENV.exists():
        raise SystemExit(".env 가 없다. 먼저 인자 없이 실행한다")
    text = ENV.read_text(encoding="utf-8")
    present = {ln.split("=", 1)[0].strip() for ln in text.splitlines() if "=" in ln and not ln.lstrip().startswith("#")}
    added = [k for k in LATER_SECRETS if k not in present]
    if added:
        lines = [] if text.endswith("\n") or not text else [""]
        for k in added:
            lines += [f"# {LATER_SECRETS[k]}", f"{k}={secrets.token_urlsafe(32)}"]
        ENV.write_text(text + "\n".join(lines) + "\n", encoding="utf-8")
    print(f"추가: {', '.join(added) or '없음(이미 있음)'} (값은 출력하지 않음)")


def main() -> None:
    if "--add-missing" in sys.argv:
        return add_missing()
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
        *(f"{k}={secrets.token_urlsafe(32)}" for k in LATER_SECRETS),
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
