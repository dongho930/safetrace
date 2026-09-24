"""규칙 기반 특징 가중치(1차 버전). 이 표의 해시가 model_meta.model_hash 에 들어가 재현성을 보장한다."""

from __future__ import annotations

import hashlib
import json
import math

from safetrace.schemas import ThreatType

P, S, G, M, X = (ThreatType.PHISHING, ThreatType.SCAM, ThreatType.ILLEGAL_GAMBLING_SUSPECTED,
                 ThreatType.MALWARE, ThreatType.OTHER)

RULES_VERSION = "st-rules-1.1"  # 1.1: domain_official 감점 추가(D3 표본 오탐 대응)

# feature → {threat: weight}
WEIGHTS: dict[str, dict[ThreatType, float]] = {
    "domain_official": {P: -3.5, S: -2.5, G: -2.5, M: -1.5},
    "url_ip_host": {P: 1.0, M: 0.8, X: 0.5},
    "url_punycode": {P: 1.2},
    "url_suspicious_tld": {P: 0.5, S: 0.5, G: 0.6},
    "url_many_subdomains": {P: 0.7},
    "url_long_or_hyphenated": {P: 0.5},
    "url_lookalike": {P: 2.2},
    "url_shortener": {P: 0.3, S: 0.3},
    "net_redirect_chain": {P: 0.5, G: 0.7, S: 0.4},
    "net_cross_domain_final": {P: 0.4, G: 0.8, S: 0.4},
    "kw_impersonation": {P: 1.4, S: 0.4},
    "kw_credential_request": {P: 1.8},
    "kw_money_request": {S: 1.4, P: 0.5},
    "kw_urgency": {P: 0.8, S: 0.7},
    "kw_gambling": {G: 3.0},
    "kw_scam_investment": {S: 2.4},
    "kw_malware": {M: 2.0},
    "form_password": {P: 1.6},
    "form_card": {P: 1.4, S: 0.8},
    "form_id_number": {P: 1.4, S: 0.4},
    "form_phone": {P: 0.4, S: 0.5},
    "form_external_action": {P: 1.2},
    "form_password_no_tls": {P: 1.0},
    "net_download_attempt": {M: 2.5},
    "net_popup_attempt": {G: 0.4, S: 0.3, M: 0.3},
    "net_many_third_party": {G: 0.3},
    "dom_many_iframes": {G: 0.3, M: 0.3},
    "dom_executable_link": {M: 2.2},
}
BIAS = -2.6  # 특징이 없으면 신뢰도 ≈ 0.07


def logistic(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def rules_hash() -> str:
    payload = json.dumps({"v": RULES_VERSION, "bias": BIAS,
                          "w": {f: {t.value: w for t, w in m.items()} for f, m in WEIGHTS.items()}},
                         sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]
