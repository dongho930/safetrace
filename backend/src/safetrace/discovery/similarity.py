"""사칭 대상과 닮은 유사 도메인 판별: 편집 거리·호모글리프·Punycode·브랜드 결합(combosquatting)."""

from __future__ import annotations

import unicodedata
from functools import lru_cache

import idna

from safetrace.discovery.allowlist import is_allowlisted, load_allowlist
from safetrace.security.url_policy import MULTI_LABEL_SUFFIXES

MIN_BRAND_LEN = 5
# 일반 단어라 브랜드로 쓰면 오탐이 많은 라벨
GENERIC_LABELS = frozenset({"google", "apple", "naver", "daum", "kakao", "live", "office", "korea", "store"})

CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ԁ": "d", "ɡ": "g", "ո": "n", "ս": "u", "ѕ": "s", "ԝ": "w", "ı": "i", "ℓ": "l",
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "@": "a", "$": "s",
})


def skeleton(s: str) -> str:
    s = unicodedata.normalize("NFKC", s).lower().translate(CONFUSABLES)
    s = "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))
    return s.replace("rn", "m").replace("vv", "w").replace("-", "").replace("_", "")


def levenshtein(a: str, b: str, cap: int = 3) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _strip_suffix(domain: str) -> str:
    labels = domain.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[:-2])
    return ".".join(labels[:-1])


@lru_cache
def brand_index() -> dict[str, str]:
    """브랜드 라벨 skeleton → 공식 등록 도메인"""
    out: dict[str, str] = {}
    for d in load_allowlist():
        label = _strip_suffix(d).split(".")[-1]
        if len(label) >= MIN_BRAND_LEN and label not in GENERIC_LABELS:
            out.setdefault(skeleton(label), d)
    return out


def _unicode_host(host: str) -> str:
    try:
        return idna.decode(host) if "xn--" in host else host
    except idna.IDNAError:
        return host


def lookalike_target(host: str) -> str | None:
    """유사 도메인이면 사칭 대상으로 추정되는 공식 도메인을, 아니면 None 을 반환한다."""
    host = host.lower().rstrip(".")
    if not host or is_allowlisted(host):
        return None
    uhost = _unicode_host(host)
    body = _strip_suffix(uhost) or uhost
    tokens = [t for part in body.split(".") for t in part.split("-") if t]
    joined = skeleton(body.replace(".", ""))
    brands = brand_index()
    for tok in tokens:
        sk = skeleton(tok)
        if sk in brands:
            return brands[sk]
    for sk_brand, domain in brands.items():
        if len(sk_brand) >= 6 and sk_brand in joined:
            return domain
        if len(sk_brand) >= 6 and any(levenshtein(skeleton(t), sk_brand, 1) == 1 for t in tokens):
            return domain
    return None
