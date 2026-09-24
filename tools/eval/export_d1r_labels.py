"""D1-R 라벨 이벤트(labels/events.jsonl) → 평가용 labels.csv + 일치도 요약.

    python tools/eval/export_d1r_labels.py [--root data/d1r] [--out data/d1r/labels.csv]

표본 비율·salt·라벨러는 콘솔(API)과 같은 설정(SAFETRACE_LABELING_*)을 쓴다. 최종 라벨이 정해진
(AGREED·CONSENSUS) 스냅샷만 내보내고, kappa 는 합의 전 독립 라벨로 계산한다.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from safetrace.config import Settings
from safetrace.labeling.store import LabelStore


def main() -> None:
    s = Settings()
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(s.d1r_dir))
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    root = Path(args.root)
    store = LabelStore(root, s.labeling_sample_rate, s.labeling_salt, s.labeling_labelers)
    out = Path(args.out) if args.out else root / "labels.csv"
    out.write_text(store.export_csv(), encoding="utf-8")
    summary = store.summary("")
    summary.pop("is_labeler", None)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
