"""관찰 결과 → 구조화 특징. 각 특징은 근거가 된 evidence_id 를 가진다(기획서 2.3 입력 계층).

페이지 문구는 '데이터'로만 다룬다. 특징 추출은 고정 사전·규칙이며 페이지 내용이 추출 로직을 바꿀 수 없다.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlsplit

from safetrace.discovery.allowlist import is_official_host
from safetrace.discovery.similarity import lookalike_target
from safetrace.schemas import EvidenceType, Observation
from safetrace.security.url_policy import registrable_domain

SUSPICIOUS_TLDS = frozenset({
    "xyz", "top", "icu", "click", "shop", "live", "buzz", "cfd", "sbs", "rest", "monster", "cyou",
    "online", "site", "store", "vip", "work", "fun", "win", "bet", "casino", "tk", "ml", "ga", "cf", "gq",
})
SHORTENERS = frozenset({"bit.ly", "t.co", "tinyurl.com", "han.gl", "me2.do", "vo.la", "url.kr", "is.gd", "buly.kr"})

# 키워드 사전(ko/en). 공개 주의보·문헌에서 흔한 표현만 담고, 운영 중 평가셋으로 보정한다.
KEYWORDS: dict[str, tuple[str, ...]] = {
    "kw_impersonation": (
        "정부24", "국민건강보험", "건강보험공단", "국세청", "홈택스", "경찰청", "검찰", "금융감독원", "우체국",
        "택배", "cj대한통운", "한진택배", "롯데택배", "로젠", "국민은행", "신한은행", "우리은행", "하나은행",
        "농협", "카카오뱅크", "토스", "카드사", "통신사", "유심", "보호나라", "kisa", "교통민원24", "이파인",
        "민원24", "정부", "지원금", "환급금", "재난지원금",
    ),
    "kw_credential_request": (
        "비밀번호", "인증번호", "otp", "보안카드", "공인인증서", "공동인증서", "주민등록번호", "주민번호",
        "계좌번호", "카드번호", "cvc", "유효기간", "본인확인", "본인인증", "password", "verify your account",
        "login to continue", "sign in to", "신분증",
    ),
    "kw_money_request": (
        "입금", "송금", "이체", "결제", "수수료", "환불", "미납", "과태료", "벌금", "배송비", "관세", "보증금",
        "선입금", "payment", "wire transfer",
    ),
    "kw_urgency": (
        "긴급", "즉시", "오늘까지", "24시간", "정지", "만료", "차단 예정", "압류", "마지막 안내", "미확인 시",
        "urgent", "suspended", "immediately", "expire",
    ),
    "kw_gambling": (
        "카지노", "바카라", "슬롯", "토토", "스포츠토토", "배팅", "베팅", "첫충", "매충", "충전", "환전",
        "롤링", "꽁머니", "파워볼", "홀덤", "라이브카지노", "먹튀", "casino", "baccarat", "betting", "jackpot",
    ),
    "kw_scam_investment": (
        "고수익", "원금보장", "원금 보장", "투자", "리딩방", "수익률", "코인", "재테크", "무위험", "당첨",
        "경품", "이벤트 당첨", "선착순", "무료 증정", "대출 승인", "저금리 대환", "guaranteed profit",
    ),
    "kw_malware": (
        "앱 설치", "apk", "보안 업데이트", "플러그인 설치", "보안 프로그램 설치", "다운로드 후 실행",
        "필수 앱", "install the app", "update required", "download now",
    ),
}


@dataclass(frozen=True)
class Feature:
    name: str
    value: float  # 0~1 강도
    evidence_type: EvidenceType
    detail: str


def _norm_text(s: str) -> str:
    return unicodedata.normalize("NFKC", s).lower()


def _kw_hits(text: str, words: tuple[str, ...]) -> list[str]:
    return [w for w in words if w in text][:8]


def extract_features(obs: Observation) -> list[Feature]:
    feats: list[Feature] = []
    OBS, SHOT = EvidenceType.OBSERVATION, EvidenceType.SCREENSHOT

    def add(name: str, value: float, et: EvidenceType, detail: str) -> None:
        if value > 0:
            feats.append(Feature(name, min(1.0, value), et, detail[:280]))

    final = obs.final_url or obs.requested_url
    host = (urlsplit(final).hostname or "").lower()
    start_host = (urlsplit(obs.requested_url).hostname or "").lower()

    # URL/도메인
    if re.fullmatch(r"[\d.]+|[0-9a-f:]+", host):
        add("url_ip_host", 1.0, OBS, f"호스트가 IP 주소: {host}")
    if "xn--" in host:
        add("url_punycode", 1.0, OBS, f"Punycode(국제화) 도메인: {host}")
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        add("url_suspicious_tld", 0.7, OBS, f"악용 빈도가 높은 TLD: .{tld}")
    if host.count(".") >= 4:
        add("url_many_subdomains", 0.6, OBS, f"과도한 하위 도메인 단계: {host}")
    if host.count("-") >= 3 or len(host) > 40:
        add("url_long_or_hyphenated", 0.5, OBS, f"긴/하이픈 많은 호스트: {host}")
    if host and is_official_host(host):
        # 공식 도메인에서 기관명·환급 문구가 나오는 것은 사칭이 아니다(D3 오탐 대응). 감점이며 판정 근거로도 제시된다.
        add("domain_official", 1.0, OBS, f"최종 도메인이 공식 허용목록에 있음: {host}")
    target = lookalike_target(host)
    if target:
        add("url_lookalike", 1.0, OBS, f"'{target}' 유사 도메인: {host}")
    if registrable_domain(start_host) in SHORTENERS:
        add("url_shortener", 0.5, OBS, f"단축 URL 경유: {start_host}")
    hops = len(obs.redirect_chain) - 1
    if hops >= 2:
        add("net_redirect_chain", min(1.0, hops / 4), OBS, f"리다이렉트 {hops}단계")
    if start_host and host and registrable_domain(start_host) != registrable_domain(host):
        add("net_cross_domain_final", 0.8, OBS, f"최종 도메인 변경: {start_host} → {host}")

    # 본문/화면
    text = _norm_text(" ".join((obs.dom_summary.title, obs.dom_summary.text_excerpt)))
    for name, words in KEYWORDS.items():
        hits = _kw_hits(text, tuple(_norm_text(w) for w in words))
        if hits:
            add(name, min(1.0, 0.45 + 0.2 * len(hits)), SHOT, "화면 문구: " + ", ".join(hits))

    # DOM/폼
    for f in obs.forms:
        if f.has_password:
            add("form_password", 1.0, OBS, f"비밀번호 입력 필드(action={f.action[:120]})")
        if f.has_card_like:
            add("form_card", 1.0, OBS, "카드번호/CVC 형태 입력 필드")
        if f.has_id_number_like:
            add("form_id_number", 1.0, OBS, "주민등록번호/생년월일 형태 입력 필드")
        if f.has_phone:
            add("form_phone", 0.6, OBS, "전화번호 입력 필드")
        if f.external_action:
            add("form_external_action", 0.9, OBS, f"외부 도메인으로 폼 전송: {f.action[:120]}")
    if any(f.has_password for f in obs.forms) and final.startswith("http://"):
        add("form_password_no_tls", 1.0, OBS, "암호화되지 않은(HTTP) 페이지의 비밀번호 입력")

    # 네트워크/행동
    if obs.downloads_blocked:
        add("net_download_attempt", 1.0, OBS, f"자동 다운로드 시도 {obs.downloads_blocked}건 차단")
    if obs.popups_blocked:
        add("net_popup_attempt", 0.5, OBS, f"팝업 시도 {obs.popups_blocked}건 차단")
    n3 = len(obs.request_summary.third_party_domains)
    if n3 >= 15:
        add("net_many_third_party", min(1.0, n3 / 40), OBS, f"외부 도메인 {n3}개 요청")
    if obs.dom_summary.iframe_count >= 3:
        add("dom_many_iframes", 0.5, OBS, f"iframe {obs.dom_summary.iframe_count}개")
    if any(u.lower().split("?")[0].endswith((".apk", ".exe", ".msi", ".scr")) for u in
           (link.url for link in obs.observed_links)):
        add("dom_executable_link", 1.0, OBS, "실행 파일(.apk/.exe 등) 링크")
    return feats


def evidence_richness(obs: Observation) -> float:
    """증거 충분성 0~1. 낮으면 UNKNOWN 으로 보류한다."""
    score = 0.0
    if obs.reachable:
        score += 0.3
    if len(obs.dom_summary.text_excerpt) >= 40:
        score += 0.4
    elif obs.dom_summary.text_excerpt:
        score += 0.15
    if obs.forms:
        score += 0.2
    if obs.dom_summary.title:
        score += 0.1
    return min(1.0, score)
