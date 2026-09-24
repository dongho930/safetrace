"""D1-S 평가 실행기: R1(동적 증거 포착, 정적 기준선 대비)·R3(유형별 Macro-F1)·R4(근거 제시율).

    python tools/eval/run_d1s.py [--limit N] [--out reports/d1s_eval.json]

- 로컬 시험 사이트(127.0.0.1)만 대상으로 하며 실제 위협 사이트에 접속하지 않는다.
- 정적 기준선: JS 없이 최초 HTML 만 받고(리다이렉트는 HTTP 3xx 만 추종) 같은 특징 추출·엔진을 적용한다.
- UNKNOWN 은 오답 처리하지 않고 별도 집계한다(보류 비율 함께 보고).
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

import httpx
from safetrace.agent.browser import AgentLimits, BrowserAgent
from safetrace.agent.extract import extract
from safetrace.ai.engine import DecisionEngine
from safetrace.schemas import EvidenceType, Observation, ReviewState
from safetrace.security.url_policy import UrlPolicy

ROOT = Path(__file__).resolve().parents[2]
D1S = ROOT / "data" / "d1s"
LABELS = ["PHISHING", "SCAM", "ILLEGAL_GAMBLING_SUSPECTED", "BENIGN"]
EV = {EvidenceType.SCREENSHOT: "ev_s", EvidenceType.HTML: "ev_h", EvidenceType.OBSERVATION: "ev_o"}


def predicted(a) -> str:
    if a.state == ReviewState.UNKNOWN:
        return "UNKNOWN"
    return a.threat_types[0].type.value


def key_signal_captured(obs: Observation, label: str) -> bool:
    """정답 페이지의 핵심 징후가 관찰에 드러났는가(R1)."""
    if label == "PHISHING":
        return any(f.has_password or f.has_id_number_like or f.has_card_like for f in obs.forms)
    if label == "SCAM":
        return "입금" in obs.dom_summary.text_excerpt or "수익" in obs.dom_summary.text_excerpt \
            or "당첨" in obs.dom_summary.text_excerpt or "대출" in obs.dom_summary.text_excerpt
    if label == "ILLEGAL_GAMBLING_SUSPECTED":
        return any(w in obs.dom_summary.text_excerpt for w in ("카지노", "토토", "바카라", "파워볼", "배팅"))
    return True


async def static_observe(client: httpx.AsyncClient, cid: str, url: str) -> Observation:
    r = await client.get(url, follow_redirects=True)
    summary, forms, links, _ = extract(r.text, str(r.url))
    return Observation(candidate_id=cid, requested_url=url, final_url=str(r.url), dom_summary=summary,
                       forms=forms, observed_links=links)


def macro_f1(pairs: list[tuple[str, str]]) -> dict:
    per = {}
    for lab in LABELS:
        tp = sum(1 for g, p in pairs if g == lab and p == lab)
        fp = sum(1 for g, p in pairs if g != lab and p == lab)
        fn = sum(1 for g, p in pairs if g == lab and p != lab)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        per[lab] = round(2 * prec * rec / (prec + rec), 4) if prec + rec else 0.0
    threat = [per[k] for k in LABELS if k != "BENIGN"]
    return {"per_label_f1": per, "macro_f1_threat_types": round(sum(threat) / len(threat), 4)}


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--out", default="")
    ap.add_argument("--zeroshot", action="store_true", help="규칙+로컬 제로샷 엔진으로 평가(규칙 전용 결과 병기)")
    args = ap.parse_args()
    out = args.out or str(ROOT / "reports" / ("d1s_eval_zs.json" if args.zeroshot else "d1s_eval.json"))

    rows = list(csv.DictReader(open(D1S / "labels.csv", encoding="utf-8")))
    if args.limit:
        rows = rows[: args.limit]
    # args.port 는 argparse type=int 로 검증된 정수이고 리스트 인자(셸 미사용)라 주입 불가
    server = subprocess.Popen([sys.executable, str(D1S / "serve.py"), "--port", str(args.port)])  # nosemgrep
    site = f"localhost:{args.port}"  # IP 리터럴 호스트 특징(url_ip_host)이 평가를 오염시키지 않도록
    try:
        time.sleep(1.0)
        agent = BrowserAgent(UrlPolicy(allow_hostports=frozenset({site})),
                             AgentLimits(page_timeout_s=10, settle_s=2.0, total_budget_s=40), record_video=False)
        rules_engine = DecisionEngine()
        engine = rules_engine
        if args.zeroshot:
            from safetrace.ai.zeroshot import HFZeroShot

            engine = DecisionEngine(classifier=HFZeroShot())
        results = []
        async with httpx.AsyncClient(timeout=10) as client:
            for i, row in enumerate(rows):
                url = f"http://{site}{row['entry_path']}"
                dyn = (await agent.investigate(f"d1s_{i}", url)).observation
                sta = await static_observe(client, f"d1s_{i}", url)
                a_dyn, a_sta = engine.analyze(dyn, EV), engine.analyze(sta, EV)
                results.append({
                    "page_id": row["page_id"], "label": row["label"], "variant": row["variant"],
                    "dynamic_pred": predicted(a_dyn), "static_pred": predicted(a_sta),
                    "dynamic_pred_rules": predicted(rules_engine.analyze(dyn, EV)),
                    "dynamic_top": a_dyn.threat_types[0].model_dump(mode="json"),
                    "dynamic_signal": key_signal_captured(dyn, row["label"]),
                    "static_signal": key_signal_captured(sta, row["label"]),
                    "final_url_ok": dyn.final_url.endswith(row["final_path"]),
                    "evidence_links_ok": all(t.evidence_links for t in a_dyn.threat_types),
                })
                print(f"[{i + 1}/{len(rows)}] {row['page_id']:<10} {row['variant']:<10} "
                      f"dyn={results[-1]['dynamic_pred']:<27} static={results[-1]['static_pred']}", flush=True)
    finally:
        server.terminate()

    threats = [r for r in results if r["label"] != "BENIGN"]
    evasive = [r for r in threats if r["variant"] in ("delayed", "redirect", "jsredirect")]
    report = {
        "dataset": "d1s-1.0", "engine": engine.model_version, "n": len(results),
        "R1_dynamic_signal_capture_evasive": round(sum(r["dynamic_signal"] for r in evasive) / max(1, len(evasive)), 4),
        "R1_static_baseline_capture_evasive": round(sum(r["static_signal"] for r in evasive) / max(1, len(evasive)), 4),
        "final_url_reached": round(sum(r["final_url_ok"] for r in results) / max(1, len(results)), 4),
        "R3_dynamic": macro_f1([(r["label"], r["dynamic_pred"]) for r in results]),
        "R3_dynamic_rules_only": macro_f1([(r["label"], r["dynamic_pred_rules"]) for r in results]),
        "R3_static": macro_f1([(r["label"], r["static_pred"]) for r in results]),
        "unknown_rate_dynamic": round(sum(r["dynamic_pred"] == "UNKNOWN" for r in results) / max(1, len(results)), 4),
        "benign_flagged_review_required": sum(1 for r in results if r["label"] == "BENIGN"
                                              and r["dynamic_pred"] != "UNKNOWN"),
        "benign_flagged_review_required_rules_only": sum(1 for r in results if r["label"] == "BENIGN"
                                                         and r["dynamic_pred_rules"] != "UNKNOWN"),
        "R4_evidence_link_rate": round(sum(r["evidence_links_ok"] for r in results) / max(1, len(results)), 4),
        "confusion_dynamic": Counter(f"{r['label']}->{r['dynamic_pred']}" for r in results),
        "items": results,
    }
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k != "items"}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
