"""로컬 개발 실행기(도커 없이): signer + api(in-process worker) + D1-S 시험 사이트.

    python scripts/dev_local.py          # 먼저 scripts/gen_secrets.py 실행
    cd frontend && npm run dev           # http://127.0.0.1:5173

로컬 모드는 egress 프록시가 없으므로 D1-S(localhost:8765)와 공개 정상 사이트만 조사한다.
실제 위협 URL 은 infra/docker-compose.yml 격리 환경에서만 다룬다.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# 다른 개발 도구와 잘 겹치지 않는 포트. 바꾸려면 환경변수 SAFETRACE_DEV_SIGNER_PORT 등을 지정한다.
# api 포트는 frontend/vite.config.ts 의 프록시 대상(8000)과 맞아야 한다.
PORTS = {
    "signer": int(os.environ.get("SAFETRACE_DEV_SIGNER_PORT", "18081")),
    "api": 8000,
    "d1s": int(os.environ.get("SAFETRACE_DEV_D1S_PORT", "8765")),
}


def port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def load_env() -> dict[str, str]:
    env = dict(os.environ)
    path = ROOT / ".env"
    if not path.exists():
        sys.exit(".env 가 없다. 먼저 python scripts/gen_secrets.py 를 실행한다.")
    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env.setdefault(k.strip(), v.strip())
    env.update({
        "SAFETRACE_ENV": "dev",
        "SAFETRACE_INPROC_WORKER": "1",
        "SAFETRACE_DATA_DIR": str(ROOT / "var"),
        "SAFETRACE_D1R_DIR": str(ROOT / "data" / "d1r"),
        "SAFETRACE_SIGNER_STATE": str(ROOT / "var" / "signer" / "state.json"),
        "SAFETRACE_SIGNER_URL": f"http://127.0.0.1:{PORTS['signer']}",
        "SAFETRACE_SIGNER_PORT": str(PORTS["signer"]),
        "SAFETRACE_TEST_ALLOW_HOSTPORTS": env.get("SAFETRACE_TEST_ALLOW_HOSTPORTS", f'["localhost:{PORTS['d1s']}"]'),
        "PYTHONIOENCODING": "utf-8",
    })
    return env


def main() -> None:
    busy = [f"{name}({port})" for name, port in PORTS.items() if port_in_use(port)]
    if busy:
        sys.exit("포트가 이미 사용 중이라 시작할 수 없다: " + ", ".join(busy) + "\n"
                 "- 이전에 띄운 dev_local.py 가 남아 있으면 종료한다.\n"
                 "- 다른 프로그램이 쓰는 포트면 SAFETRACE_DEV_SIGNER_PORT / SAFETRACE_DEV_D1S_PORT 로 바꾼다.\n"
                 "  (api 8000 은 frontend/vite.config.ts 프록시 대상과 함께 바꿔야 한다)")
    env = load_env()
    py = sys.executable
    if not (ROOT / "data" / "d1s" / "site").exists():
        subprocess.run([py, str(ROOT / "data" / "d1s" / "generate.py")], check=True)
    procs = [
        subprocess.Popen([py, "-m", "safetrace.signer.app"], env=env, cwd=ROOT),
        subprocess.Popen([py, str(ROOT / "data" / "d1s" / "serve.py"), "--port", str(PORTS["d1s"])], env=env, cwd=ROOT),
    ]
    time.sleep(1.5)
    procs.append(subprocess.Popen([py, "-m", "safetrace.api.app"], env=env, cwd=ROOT))
    names = ["signer", "d1s", "api"]
    print(f"signer :{PORTS['signer']} · api :8000 · D1-S http://localhost:{PORTS['d1s']}/  (Ctrl+C 로 종료)")
    try:
        while all(p.poll() is None for p in procs):
            time.sleep(1)
        dead = [n for n, p in zip(names, procs, strict=True) if p.poll() is not None]
        print(f"\n[dev_local] 프로세스가 종료되어 전체를 멈춘다: {', '.join(dead)} — 위 로그의 오류를 확인한다.")
    except KeyboardInterrupt:
        pass
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()


if __name__ == "__main__":
    main()
