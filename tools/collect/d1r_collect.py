"""D1-R 실제 위협 스냅샷 수집기(격리 환경 전용, 2주차까지 매일 1회).

    docker compose --env-file .env -f infra/docker-compose.yml --profile collector up -d collector

- 격리 Worker 망 + egress 프록시 경유가 아니면 실행을 거부한다(업무 PC 에서 실제 위협 사이트에 접속하지 않음).
- 소스: OpenPhish 커뮤니티 피드, URLhaus(온라인 목록), KISA 피싱사이트 URL CSV(선택). 이용 조건을 확인한 공개 피드만.
- URL 당 1회만 수집(전역 인덱스로 중복 방지). HAR(본문 포함)·스크린샷·DOM·관찰 JSON 을 저장하고
  각 파일 SHA-256 을 meta.json 에 기록한 뒤 동결한다. 평가는 HAR 재생(tools/eval/replay_d1r.py)으로만 한다.
- 접속 불가 URL 은 UNREACHABLE 로 인덱스에만 기록한다(기획서 2.2 공공데이터 활용).
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from itertools import zip_longest
from pathlib import Path

import httpx
from safetrace.agent.browser import AgentLimits, BrowserAgent
from safetrace.ingest.kisa import load_csv
from safetrace.schemas import EvidenceType
from safetrace.security.url_policy import PolicyViolation, UrlPolicy, normalize_url

FEEDS = {
    # 2026-09 기준 openphish.com/feed.txt 는 GitHub 공개 피드로 302 이동
    "openphish": "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/text_online/",
}
FILES = {EvidenceType.HAR: "trace.har.json", EvidenceType.SCREENSHOT: "screenshot.png",
         EvidenceType.HTML: "dom.html.txt", EvidenceType.OBSERVATION: "observation.json"}


def guard() -> str:
    proxy = os.environ.get("SAFETRACE_EGRESS_PROXY", "")
    if not proxy or os.environ.get("SAFETRACE_D1R_ISOLATED") != "1":
        sys.exit("거부: D1-R 수집은 격리 Worker 망(egress 프록시 경유)에서만 실행한다. docs/08 §D1-R 참조")
    if not os.environ.get("SAFETRACE_EGRESS_DENY_TOKEN"):
        sys.exit("거부: SAFETRACE_EGRESS_DENY_TOKEN 이 없으면 프록시 거부 응답이 스냅샷으로 저장된다")
    return proxy


async def fetch_feed(client: httpx.AsyncClient, name: str, url: str, cap: int) -> list[tuple[str, str]]:
    try:
        r = await client.get(url)
        r.raise_for_status()
    except httpx.HTTPError as exc:
        print(f"feed {name} unavailable: {type(exc).__name__}")
        return []
    lines = [ln.strip() for ln in r.text.splitlines() if ln.strip() and not ln.startswith("#")]
    return [(name, u) for u in lines[:cap]]


def interleave(feeds: list[list[tuple[str, str]]]) -> list[tuple[str, str]]:
    """피드별로 번갈아 뽑아 한 피드(예: URLhaus 의 IoT 페이로드 URL)가 하루 할당량을 독점하지 않게 한다."""
    return [item for group in zip_longest(*feeds) for item in group if item is not None]


async def run_once(out: Path, max_new: int, kisa_csv: Path | None, proxy: str) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    index_path = out / "index.jsonl"
    seen = set()
    if index_path.exists():
        seen = {json.loads(ln)["key"] for ln in index_path.read_text(encoding="utf-8").splitlines() if ln}

    feeds: list[list[tuple[str, str]]] = []
    async with httpx.AsyncClient(proxy=proxy, timeout=20, follow_redirects=True,
                                 headers={"User-Agent": "SafeTrace-research/0.1"}) as c:
        for name, url in FEEDS.items():
            feeds.append(await fetch_feed(c, name, url, cap=max_new * 5))
    if kisa_csv and kisa_csv.exists():
        feeds.append([("kisa", r.normalized_url) for r in load_csv(kisa_csv.read_bytes()).records])
    sources = interleave(feeds)

    agent = BrowserAgent(UrlPolicy(resolve_dns=False), AgentLimits(page_timeout_s=20, total_budget_s=60),
                         proxy=proxy, record_video=False, record_har=True,
                         egress_deny_token=os.environ.get("SAFETRACE_EGRESS_DENY_TOKEN", ""))
    day = datetime.now(UTC).strftime("%Y%m%d")
    stats = {"date": day, "collected": 0, "unreachable": 0, "skipped_seen": 0, "invalid": 0}
    with open(index_path, "a", encoding="utf-8") as index:
        for source, raw in sources:
            if stats["collected"] >= max_new:
                break
            try:
                n = normalize_url(raw)
            except PolicyViolation:
                stats["invalid"] += 1
                continue
            if n.idempotency_key in seen:
                stats["skipped_seen"] += 1
                continue
            seen.add(n.idempotency_key)
            sid = f"{day}-{n.idempotency_key[:12]}"
            res = await agent.investigate(sid, n.url)
            obs = res.observation
            entry = {"key": n.idempotency_key, "snapshot_id": sid, "source": source, "url": n.url,
                     "collected_at": datetime.now(UTC).isoformat(), "agent_version": obs.agent_version}
            if not obs.reachable or not obs.dom_summary.text_excerpt:
                entry["status"] = "UNREACHABLE"
                entry["errors"] = obs.errors + obs.policy_blocks
                stats["unreachable"] += 1
            else:
                snap = out / "snapshots" / day / sid
                snap.mkdir(parents=True, exist_ok=True)
                hashes = {}
                for et, fname in FILES.items():
                    if et in res.artifacts:
                        (snap / fname).write_bytes(res.artifacts[et])
                        hashes[fname] = hashlib.sha256(res.artifacts[et]).hexdigest()
                meta = {**entry, "final_url": obs.final_url, "files": hashes, "frozen": True}
                (snap / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
                entry["status"] = "COLLECTED"
                stats["collected"] += 1
            index.write(json.dumps(entry, ensure_ascii=False) + "\n")
            index.flush()
    return stats


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/data/d1r")
    ap.add_argument("--max-new", type=int, default=60)
    ap.add_argument("--kisa-csv", default="")
    ap.add_argument("--daily", action="store_true", help="24시간마다 반복(2주차 말까지 운영)")
    ap.add_argument("--until", default="2026-10-18", help="--daily 종료일(D1-R 스냅샷 동결일)")
    args = ap.parse_args()
    proxy = guard()
    while True:
        stats = await run_once(Path(args.out), args.max_new, Path(args.kisa_csv) if args.kisa_csv else None, proxy)
        print(json.dumps(stats, ensure_ascii=False))
        if not args.daily or datetime.now(UTC).date().isoformat() >= args.until:
            break
        await asyncio.sleep(24 * 3600)


if __name__ == "__main__":
    asyncio.run(main())
