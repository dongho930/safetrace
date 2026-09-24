"""조사 Worker 컨테이너 안에서 실행하는 네트워크 격리 검증(D2-06/07/08, 사전준비 통과 기준).

    docker compose --env-file .env -f infra/docker-compose.yml exec -T worker python - \
        < infra/scripts/verify_isolation.py

기대 결과: 내부 서비스·메타데이터·직접 인터넷 접속은 모두 실패, egress 프록시 경유 공개 사이트만 성공,
프록시 경유 내부 주소는 403(IP_NOT_PUBLIC).
"""

import json
import os
import socket
import urllib.error
import urllib.request

PROXY = os.environ.get("SAFETRACE_EGRESS_PROXY", "http://egress-proxy:3128")
results = []


def tcp(name: str, host: str, port: int, expect_ok: bool) -> None:
    try:
        with socket.create_connection((host, port), timeout=3):
            ok = True
    except OSError:
        ok = False
    results.append({"check": name, "expect": "reachable" if expect_ok else "blocked",
                    "actual": "reachable" if ok else "blocked", "pass": ok == expect_ok})


def via_proxy(name: str, url: str, expect_status: int) -> None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": PROXY, "https": PROXY}))
    try:
        status = opener.open(url, timeout=10).status
    except urllib.error.HTTPError as e:
        status = e.code
    except (urllib.error.URLError, OSError):
        status = -1
    results.append({"check": name, "expect": expect_status, "actual": status, "pass": status == expect_status})


tcp("internal api:8000", "api", 8000, False)
tcp("internal signer:8081", "signer", 8081, False)
tcp("internal postgres:5432", "postgres", 5432, False)
tcp("internal redis:6379", "redis", 6379, False)
tcp("cloud metadata 169.254.169.254:80", "169.254.169.254", 80, False)
tcp("direct internet 1.1.1.1:443", "1.1.1.1", 443, False)
tcp("ingest-gw:8080 (allowed)", "ingest-gw", 8080, True)
tcp("egress-proxy:3128 (allowed)", "egress-proxy", 3128, True)
via_proxy("proxy -> https://example.com/", "https://example.com/", 200)
via_proxy("proxy -> http://169.254.169.254/", "http://169.254.169.254/latest/meta-data/", 403)
via_proxy("proxy -> http://api:8000/ (internal DNS)", "http://api:8000/healthz", 403)
via_proxy("proxy -> http://10.0.0.1/", "http://10.0.0.1/", 403)

print(json.dumps(results, ensure_ascii=False, indent=2))
failed = [r for r in results if not r["pass"]]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
raise SystemExit(1 if failed else 0)
