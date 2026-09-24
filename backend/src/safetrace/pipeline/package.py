"""③ 공공기관 검토 패키지(사전준비: JSON 미리보기. PDF·기관 양식 변환은 3주차 Package Builder)."""

from __future__ import annotations

from typing import Any

from safetrace.schemas import (
    AIAnalysis,
    Candidate,
    ChainVerification,
    Evidence,
    Observation,
    Reputation,
    Review,
    utcnow,
)

DISCLAIMER = (
    "AI confidence 는 모델의 기술적 신뢰도이며 법적 위법성의 확률이 아니다. "
    "외부 평판 DB 미등재는 정상의 근거가 아니다. 최종 판정은 담당자가 한다."
)


def build_package(
    cand: Candidate,
    obs: Observation | None,
    evidence: list[Evidence],
    verification: ChainVerification,
    analysis: AIAnalysis | None,
    reputation: list[Reputation],
    review: Review | None,
    impersonates: list[str],
) -> dict[str, Any]:
    return {
        "package_version": "0.1-preview",
        "generated_at": utcnow().isoformat(),
        "disclaimer": DISCLAIMER,
        "case_overview": {
            "case_id": cand.case_id,
            "candidate_id": cand.candidate_id,
            "source": cand.source,
            "original_url": cand.original_url,
            "normalized_url": cand.normalized_url,
            "discovered_from": cand.discovered_from,
            "relation": cand.relation,
            "depth": cand.depth,
            "submitted_at": cand.created_at.isoformat(),
            "investigated_at": obs.finished_at.isoformat() if obs and obs.finished_at else None,
            "final_url": obs.final_url if obs else None,
            "status": cand.status,
        },
        "evidence": {
            "items": [
                {"evidence_id": e.evidence_id, "type": e.type, "sha256": e.sha256, "size": e.size,
                 "captured_at": e.captured_at.isoformat(), "seq": e.seq, "hmac_key_id": e.key_id}
                for e in evidence
            ],
            "integrity": verification.model_dump(mode="json"),
            "redirect_chain": [h.model_dump(mode="json") for h in (obs.redirect_chain if obs else [])],
            "forms": [f.model_dump(mode="json") for f in (obs.forms if obs else [])],
            "request_summary": obs.request_summary.model_dump(mode="json") if obs else None,
            "impersonation_targets": impersonates,
        },
        "ai_analysis": analysis.model_dump(mode="json") if analysis else None,
        "reputation": [r.model_dump(mode="json") for r in reputation],
        "reviewer_area": review.model_dump(mode="json") if review else {"decision": None, "note": "미검토"},
    }
