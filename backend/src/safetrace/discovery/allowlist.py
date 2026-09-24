"""정상 도메인 허용목록. 허용목록 도메인은 재큐잉하지 않고 '사칭 대상(IMPERSONATES)' 관계로만 기록한다."""

from __future__ import annotations

from functools import lru_cache
from importlib import resources

from safetrace.security.url_policy import registrable_domain

# 공공기관 접미사: 하위 도메인 전체를 정상 기관 도메인으로 본다.
TRUSTED_SUFFIXES = (".go.kr", ".mil.kr")

# 공용 CDN·광고·분석 도메인: 재큐잉 우선순위 감점(허용목록과 별개로 조사 가치가 낮음).
COMMON_INFRA = frozenset({
    "googleapis.com", "gstatic.com", "googletagmanager.com", "google-analytics.com", "doubleclick.net",
    "cloudflare.com", "jsdelivr.net", "cdnjs.cloudflare.com", "akamaihd.net", "fontawesome.com",
    "jquery.com", "unpkg.com", "bootstrapcdn.com", "fbcdn.net", "kakaocdn.net", "pstatic.net",
    "daumcdn.net", "cloudfront.net", "hotjar.com", "clarity.ms", "criteo.com", "adnxs.com",
})


# 허용목록 도메인이라도 누구나 콘텐츠를 올릴 수 있는 호스트: 공식 도메인 신뢰 감점에서 제외한다.
USER_CONTENT_HOSTS = (
    "sites.google.com", "docs.google.com", "forms.gle", "drive.google.com", "storage.googleapis.com",
    "firebaseapp.com", "web.app", "github.io", "githubusercontent.com", "blogspot.com", "notion.site",
    "cdn.jsdelivr.net", "pages.dev", "workers.dev", "vercel.app", "netlify.app", "blog.naver.com",
    "cafe.naver.com", "modoo.at", "form.office.com", "forms.office.com", "1drv.ms", "sharepoint.com",
)


def is_official_host(host: str) -> bool:
    """공식(허용목록) 도메인이면서 사용자 콘텐츠 호스트가 아닌가."""
    h = host.lower().rstrip(".")
    if any(h == u or h.endswith("." + u) for u in USER_CONTENT_HOSTS):
        return False
    return is_allowlisted(h)


@lru_cache
def load_allowlist() -> frozenset[str]:
    text = resources.files("safetrace.data").joinpath("allowlist.txt").read_text(encoding="utf-8")
    return frozenset(
        line.strip().lower() for line in text.splitlines() if line.strip() and not line.startswith("#")
    )


def is_allowlisted(host: str) -> bool:
    h = host.lower().rstrip(".")
    if h.endswith(TRUSTED_SUFFIXES):
        return True
    allow = load_allowlist()
    return h in allow or registrable_domain(h) in allow


def is_common_infra(host: str) -> bool:
    h = host.lower()
    return h in COMMON_INFRA or registrable_domain(h) in COMMON_INFRA
