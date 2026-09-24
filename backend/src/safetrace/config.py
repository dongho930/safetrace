"""환경변수 기반 설정. 비밀값은 코드·로그에 남기지 않는다(기획서 2.7 비밀 정보 노출)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SAFETRACE_", env_file=".env", extra="ignore")

    env: str = "dev"
    data_dir: Path = Path("./var")

    # 서명 서비스: API 는 URL·토큰만 알고 HMAC 키는 갖지 않는다.
    signer_url: str = "http://127.0.0.1:8081"
    signer_token: SecretStr = SecretStr("")

    # 조사 Worker ↔ 수집 API 인증 토큰. Worker 는 DB·큐 자격증명을 갖지 않는다.
    worker_token: SecretStr = SecretStr("")

    # Worker 가 사용할 egress 프록시(2차 SSRF 방어). 비어 있으면 직접 접속(로컬 개발 전용).
    egress_proxy: str = ""

    safe_browsing_api_key: SecretStr = SecretStr("")
    # 네이버 검색 API(웹문서) Seed, F-03 1주차 연동. developers.naver.com 애플리케이션의 Client ID/Secret
    naver_client_id: str = ""
    naver_client_secret: SecretStr = SecretStr("")

    # 탐색·조사 예산(기획서 2.2 / docs/05)
    max_depth: int = Field(default=2, ge=0, le=5)
    max_candidates_per_case: int = Field(default=30, ge=1, le=500)
    max_candidates_per_domain: int = Field(default=5, ge=1, le=100)
    case_time_budget_s: int = Field(default=600, ge=30)
    page_timeout_s: int = Field(default=20, ge=5, le=120)
    max_requests_per_page: int = Field(default=300, ge=10, le=5000)
    max_redirects: int = Field(default=10, ge=1, le=30)
    max_html_bytes: int = Field(default=2_000_000, ge=10_000)

    # 개발용 CORS 출처(프론트 Vite dev 서버)
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    # 로컬 시험 사이트(D1-S·D4) host:port 명시 허용. env=prod 에서는 무시된다.
    test_allow_hostports: list[str] = []

    def allowed_test_hostports(self) -> frozenset[str]:
        return frozenset() if self.env == "prod" else frozenset(self.test_allow_hostports)


@lru_cache
def get_settings() -> Settings:
    return Settings()
