"""D1-R 평가: 동결된 스냅샷을 HAR 재생으로만 다시 렌더링해 AI 유형 분석(R3)·정상 오인(R7)을 측정한다.

    python tools/eval/replay_d1r.py --root data/d1r --labels data/d1r/labels.csv

- 재생 모드는 HAR 에 없는 요청을 모두 abort 하므로 실제 위협 사이트에 다시 접속하지 않는다.
- labels.csv: snapshot_id,label_a,label_b,final_label,excluded_reason,note,agreement
  (콘솔 라벨링 → tools/eval/export_d1r_labels.py 로 생성. agreement = AGREED(독립 일치) | CONSENSUS(합의))
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
from collections import Counter
from pathlib import Path

from safetrace.agent.browser import AgentLimits, BrowserAgent
from safetrace.ai.engine import DecisionEngine
from safetrace.schemas import EvidenceType, ReviewState
from safetrace.security.url_policy import UrlPolicy

EV = {EvidenceType.SCREENSHOT: "ev_s", EvidenceType.HTML: "ev_h", EvidenceType.OBSERVATION: "ev_o"}


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="data/d1r")
    ap.add_argument("--labels", default="data/d1r/labels.csv")
    ap.add_argument("--out", default="reports/d1r_eval.json")
    args = ap.parse_args()
    root = Path(args.root)
    labels = {r["snapshot_id"]: r for r in csv.DictReader(open(args.labels, encoding="utf-8"))
              if r.get("final_label") and not r.get("excluded_reason")}
    engine = DecisionEngine()
    items = []
    for meta_path in sorted(root.glob("snapshots/*/*/meta.json")):
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        sid = meta["snapshot_id"]
        if sid not in labels:
            continue
        agent = BrowserAgent(UrlPolicy(resolve_dns=False), AgentLimits(total_budget_s=40), record_video=False,
                             har_replay=meta_path.parent / "trace.har.json")
        obs = (await agent.investigate(sid, meta["url"])).observation
        a = engine.analyze(obs, EV)
        pred = "UNKNOWN" if a.state == ReviewState.UNKNOWN else a.threat_types[0].type.value
        items.append({"snapshot_id": sid, "source": meta["source"], "label": labels[sid]["final_label"],
                      "agreement": labels[sid].get("agreement", ""), "pred": pred,
                      "confidence": a.threat_types[0].confidence})
        print(sid, labels[sid]["final_label"], pred, flush=True)
    report = {"engine": engine.model_version, "n": len(items),
              "by_source": Counter(i["source"] for i in items),
              "by_agreement": Counter(i["agreement"] for i in items),
              "confusion": Counter(f"{i['label']}->{i['pred']}" for i in items), "items": items}
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k != "items"}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
