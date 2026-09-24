"""D3 공개 정상 사이트 평가: 대규모 정상 사이트에서의 오탐(R7) 측정.

    python tools/eval/run_d3.py [--limit N] [--interval 5] [--out reports/d3_eval.json]

- 공개 첫 화면 1회 렌더링만 한다(로그인·폼 입력·크롤링 없음). 요청 간격(--interval, 기본 5초)을 지킨다.
- 측정: AI 상태 분포(UNKNOWN / REVIEW_REQUIRED), 고신뢰(≥0.8) 경보 수, 자동 확정 0건(구조적 보장) 확인.
- 정상 사이트이므로 기대값은 'UNKNOWN 다수, 고신뢰 경보 0에 가까움'. 결과는 있는 그대로 보고한다.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import time
from collections import Counter
from pathlib import Path

from safetrace.agent.browser import AgentLimits, BrowserAgent
from safetrace.ai.engine import DecisionEngine
from safetrace.schemas import EvidenceType, ReviewState
from safetrace.security.url_policy import UrlPolicy

ROOT = Path(__file__).resolve().parents[2]
EV = {EvidenceType.SCREENSHOT: "ev_s", EvidenceType.HTML: "ev_h", EvidenceType.OBSERVATION: "ev_o"}


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--interval", type=float, default=5.0)
    ap.add_argument("--out", default="")
    ap.add_argument("--zeroshot", action="store_true", help="규칙+로컬 제로샷 엔진으로 평가(규칙 전용 상태 병기)")
    args = ap.parse_args()
    out = args.out or str(ROOT / "reports" / ("d3_eval_zs.json" if args.zeroshot else "d3_eval.json"))
    rows = list(csv.DictReader(open(ROOT / "data" / "d3" / "benign_sites.csv", encoding="utf-8")))
    if args.limit:
        rows = rows[: args.limit]

    agent = BrowserAgent(UrlPolicy(), AgentLimits(page_timeout_s=20, settle_s=2.0, total_budget_s=45),
                         record_video=False)
    rules_engine = DecisionEngine()
    engine = rules_engine
    if args.zeroshot:
        from safetrace.ai.zeroshot import HFZeroShot

        engine = DecisionEngine(classifier=HFZeroShot())
    items = []
    for i, row in enumerate(rows):
        t0 = time.monotonic()
        obs = (await agent.investigate(row["site_id"], row["url"])).observation
        a = engine.analyze(obs, EV)
        top = a.threat_types[0]
        a_rules = rules_engine.analyze(obs, EV) if engine is not rules_engine else a
        items.append({
            "site_id": row["site_id"], "category": row["category"], "name": row["name"], "url": row["url"],
            "reachable": obs.reachable and bool(obs.dom_summary.text_excerpt), "final_url": obs.final_url,
            "state": a.state.value, "state_reason": a.state_reason, "top_type": top.type.value,
            "top_confidence": top.confidence,
            "state_rules_only": a_rules.state.value, "top_confidence_rules_only": a_rules.threat_types[0].confidence,
            "features": [link.feature for link in top.evidence_links],
            "errors": obs.errors, "policy_blocks": obs.policy_blocks,
        })
        print(f"[{i + 1}/{len(rows)}] {row['name'][:14]:<14} reach={items[-1]['reachable']!s:<5} "
              f"{a.state.value:<15} {top.type.value}:{top.confidence:.2f}", flush=True)
        await asyncio.sleep(max(0.0, args.interval - (time.monotonic() - t0)))

    reach = [x for x in items if x["reachable"]]
    report = {
        "dataset": "d3-1.0", "engine": engine.model_version, "n": len(items), "reachable": len(reach),
        "state_counts": Counter(x["state"] for x in reach),
        "review_required_rate": round(sum(x["state"] == ReviewState.REVIEW_REQUIRED for x in reach)
                                      / max(1, len(reach)), 4),
        "high_confidence_alerts(>=0.8)": sum(1 for x in reach if x["state"] == "REVIEW_REQUIRED"
                                             and x["top_confidence"] >= 0.8),
        "review_required_rules_only": sum(x["state_rules_only"] == ReviewState.REVIEW_REQUIRED for x in reach),
        "high_confidence_alerts_rules_only": sum(1 for x in reach if x["state_rules_only"] == "REVIEW_REQUIRED"
                                                 and x["top_confidence_rules_only"] >= 0.8),
        "auto_confirmed": 0,  # AI·자동화 계정은 판정 권한이 없다(decision_authority=NONE, RBAC·DB 트리거)
        "top_feature_counts_in_alerts": Counter(f for x in reach if x["state"] == "REVIEW_REQUIRED"
                                                for f in x["features"]).most_common(10),
        "items": items,
    }
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k != "items"}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
