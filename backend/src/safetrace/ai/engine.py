"""② 자체 AI Decision Engine 1차 버전: 규칙 기반 특징 + (선택) 제로샷 분류 → 구조화 출력.

운영 원칙(기획서 2.3):
- 출력은 AIAnalysis 스키마로 강제된다. threat_types 는 고정 enum, confidence 는 0~1.
- 모든 유형 후보는 evidence_links 를 가진다(R4 제시율 100%).
- 판정 권한 없음(decision_authority="NONE"). 상태는 REVIEW_REQUIRED 또는 UNKNOWN 뿐이다.
- 증거 부족·신뢰도 미달은 UNKNOWN 으로 보류한다.
"""

from __future__ import annotations

from dataclasses import dataclass

from safetrace.ai.features import Feature, evidence_richness, extract_features
from safetrace.ai.rules import BIAS, RULES_VERSION, WEIGHTS, logistic, rules_hash
from safetrace.ai.zeroshot import TextClassifier
from safetrace.schemas import (
    AIAnalysis,
    EvidenceLink,
    EvidenceType,
    ModelMeta,
    Observation,
    ReviewState,
    ThreatScore,
    ThreatType,
)

ZS_BLEND = 0.35  # 제로샷 점수 반영 비율(규칙 우선)
REPORT_MIN = 0.2  # 이 이상인 유형만 후보로 제시
UNKNOWN_BELOW = 0.45  # 최고 신뢰도가 이 미만이면 UNKNOWN
MIN_RICHNESS = 0.35  # 증거 충분성 하한


@dataclass
class DecisionEngine:
    classifier: TextClassifier | None = None

    @property
    def model_version(self) -> str:
        if self.classifier is None:
            return RULES_VERSION
        return f"{RULES_VERSION}+zs:{self.classifier.name}@{self.classifier.revision}"

    def analyze(self, obs: Observation, evidence_ids: dict[EvidenceType, str]) -> AIAnalysis:
        feats = extract_features(obs)
        logits = {t: BIAS for t in ThreatType if t != ThreatType.OTHER}
        contrib: dict[ThreatType, list[tuple[float, Feature]]] = {t: [] for t in logits}
        for f in feats:
            for t, w in WEIGHTS.get(f.name, {}).items():
                if t in logits:
                    logits[t] += w * f.value
                    contrib[t].append((w * f.value, f))
        scores = {t: logistic(v) for t, v in logits.items()}

        backend = "rules"
        if self.classifier is not None:
            text = " ".join((obs.dom_summary.title, obs.dom_summary.text_excerpt))
            try:
                zs = self.classifier.classify(text)
            except Exception:  # noqa: BLE001 - 분류기 장애는 규칙 결과로 계속 진행
                zs = {}
            if zs:
                backend = "rules+zeroshot"
                for t in scores:
                    if t in zs:
                        scores[t] = (1 - ZS_BLEND) * scores[t] + ZS_BLEND * zs[t]

        fallback_ev = (evidence_ids.get(EvidenceType.SCREENSHOT) or evidence_ids.get(EvidenceType.HTML)
                       or evidence_ids.get(EvidenceType.OBSERVATION) or "")
        threat_scores: list[ThreatScore] = []
        for t, conf in sorted(scores.items(), key=lambda kv: -kv[1]):
            if conf < REPORT_MIN and threat_scores:
                continue
            links: list[EvidenceLink] = []
            for _, f in sorted(contrib[t], key=lambda c: -c[0])[:5]:
                eid = evidence_ids.get(f.evidence_type) or evidence_ids.get(EvidenceType.OBSERVATION) or fallback_ev
                links.append(EvidenceLink(evidence_id=eid, feature=f.name, reason=f.detail))
            if not links and fallback_ev:
                links.append(EvidenceLink(evidence_id=fallback_ev, feature="text_classifier",
                                          reason="본문 텍스트 분류 점수(특정 규칙 근거 없음)"))
            threat_scores.append(ThreatScore(type=t, confidence=round(conf, 4), evidence_links=links))

        richness = evidence_richness(obs)
        top = threat_scores[0].confidence if threat_scores else 0.0
        if not obs.reachable:
            state, reason = ReviewState.UNKNOWN, "INSUFFICIENT_EVIDENCE: 접속 불가(UNREACHABLE)"
        elif richness < MIN_RICHNESS:
            state, reason = ReviewState.UNKNOWN, f"INSUFFICIENT_EVIDENCE: 증거 충분성 {richness:.2f}"
        elif top < UNKNOWN_BELOW:
            state, reason = ReviewState.UNKNOWN, f"LOW_CONFIDENCE: 최고 신뢰도 {top:.2f}"
        else:
            state, reason = ReviewState.REVIEW_REQUIRED, "담당자 검토 필요(AI 는 판정하지 않음)"
            if len(threat_scores) > 1 and threat_scores[0].confidence - threat_scores[1].confidence < 0.05:
                reason = "AMBIGUOUS: 상위 유형 간 신뢰도 차이가 작음"

        return AIAnalysis(
            candidate_id=obs.candidate_id,
            threat_types=threat_scores,
            state=state,
            state_reason=reason,
            model_meta=ModelMeta(model_version=self.model_version, model_hash=rules_hash(), backend=backend),
        )
