"""SafeTrace 핵심 데이터 스키마(설계 확정본, docs/03_data_schema.md 와 1:1 대응).

수집된 모든 값은 불신 데이터다. 문자열 필드는 길이 상한을 두고, 표시 계층에서는 이스케이프만 한다.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

Str256 = Annotated[str, Field(max_length=256)]
Str2K = Annotated[str, Field(max_length=2048)]
Sha256Hex = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:20]}"


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=False)


# ─────────────────────────── 후보(⓪ Candidate Discovery) ───────────────────────────


class SeedSource(StrEnum):
    KISA = "KISA"  # 공공데이터포털 KISA 피싱사이트 URL
    REPORT = "REPORT"  # 신고 URL(단건·CSV)
    SEARCH_API = "SEARCH_API"  # 네이버 검색 API 공식 응답
    DISCOVERED = "DISCOVERED"  # 조사 중 관찰된 후속 후보


class Relation(StrEnum):
    SEED = "SEED"
    LINK = "LINK"
    REDIRECT = "REDIRECT"
    RESOURCE = "RESOURCE"
    SCRIPT = "SCRIPT"
    FORM_ACTION = "FORM_ACTION"
    IMPERSONATES = "IMPERSONATES"  # 허용목록(사칭 대상) 도메인: 재큐잉하지 않고 관계만 기록


class CandidateStatus(StrEnum):
    DISCOVERED = "DISCOVERED"
    QUEUED = "QUEUED"
    SCREENING = "SCREENING"  # 접근 전 검사
    INVESTIGATING = "INVESTIGATING"
    ANALYZING = "ANALYZING"
    PACKAGING = "PACKAGING"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    DECIDED = "DECIDED"
    SKIPPED = "SKIPPED"  # 중복·허용목록·예산 초과
    BLOCKED = "BLOCKED"  # 안전 정책 차단(SSRF 등)
    UNREACHABLE = "UNREACHABLE"
    FAILED = "FAILED"


class ScoreReason(Strict):
    code: Str256
    weight: float
    detail: Str256 = ""


class Candidate(Strict):
    candidate_id: str = Field(default_factory=lambda: new_id("cand"))
    case_id: str
    source: SeedSource
    original_url: Str2K
    normalized_url: Str2K
    registrable_domain: Str256
    discovered_from: str | None = None
    relation: Relation = Relation.SEED
    depth: int = Field(default=0, ge=0)
    priority: float = 0.0
    score_reasons: list[ScoreReason] = []
    status: CandidateStatus = CandidateStatus.DISCOVERED
    status_reason: Str256 = ""
    idempotency_key: Sha256Hex
    created_at: datetime = Field(default_factory=utcnow)


class Case(Strict):
    case_id: str = Field(default_factory=lambda: new_id("case"))
    source: SeedSource
    original_url: Str2K
    submitted_by: Str256
    created_at: datetime = Field(default_factory=utcnow)


# ─────────────────────────── ① Browser Agent 관찰 ───────────────────────────


class RedirectHop(Strict):
    url: Str2K
    status: int | None = None
    kind: Annotated[str, Field(pattern=r"^(http|client|initial)$")]


class FormInfo(Strict):
    action: Str2K = ""
    method: Annotated[str, Field(max_length=10)] = "get"
    input_types: list[Annotated[str, Field(max_length=32)]] = []
    input_names: list[Annotated[str, Field(max_length=64)]] = []
    has_password: bool = False
    has_card_like: bool = False
    has_phone: bool = False
    has_id_number_like: bool = False
    external_action: bool = False


class DomSummary(Strict):
    title: Str256 = ""
    lang: Annotated[str, Field(max_length=16)] = ""
    text_excerpt: Annotated[str, Field(max_length=4000)] = ""
    element_count: int = 0
    script_count: int = 0
    iframe_count: int = 0
    link_count: int = 0
    html_bytes: int = 0


class RequestSummary(Strict):
    total: int = 0
    blocked: int = 0
    domains: list[Str256] = []
    third_party_domains: list[Str256] = []
    blocked_samples: list[Str2K] = []


class ObservedLink(Strict):
    url: Str2K
    relation: Relation
    text: Annotated[str, Field(max_length=200)] = ""


class Observation(Strict):
    candidate_id: str
    requested_url: Str2K
    final_url: Str2K = ""
    reachable: bool = True
    redirect_chain: list[RedirectHop] = []
    dom_summary: DomSummary = DomSummary()
    forms: list[FormInfo] = []
    request_summary: RequestSummary = RequestSummary()
    observed_links: list[ObservedLink] = []
    popups_blocked: int = 0
    downloads_blocked: int = 0
    policy_blocks: list[Str256] = []
    errors: list[Str256] = []
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None
    agent_version: Str256 = ""


# ─────────────────────────── 증거 ───────────────────────────


class EvidenceType(StrEnum):
    SCREENSHOT = "SCREENSHOT"
    HTML = "HTML"
    OBSERVATION = "OBSERVATION"  # 구조화 관찰 JSON(리다이렉트·폼·요청 메타데이터)
    VIDEO = "VIDEO"  # 렌더링 녹화
    HAR = "HAR"


class Evidence(Strict):
    evidence_id: str
    seq: int = Field(ge=1)
    case_id: str
    candidate_id: str
    type: EvidenceType
    object_path: Str2K
    sha256: Sha256Hex
    size: int = Field(ge=0)
    captured_at: datetime
    version: int = Field(default=1, ge=1)
    prev_hash: Sha256Hex
    record_hash: Sha256Hex
    hmac_sig: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    key_id: Str256


class VerifyIssue(Strict):
    seq: int
    evidence_id: str
    code: Annotated[str, Field(pattern=r"^[A-Z_]+$")]
    detail: Str256 = ""


class ChainVerification(Strict):
    ok: bool
    checked: int
    issues: list[VerifyIssue] = []
    head_hash: str = ""


# ─────────────────────────── ② AI Decision Engine ───────────────────────────


class ThreatType(StrEnum):
    PHISHING = "PHISHING"
    SCAM = "SCAM"
    ILLEGAL_GAMBLING_SUSPECTED = "ILLEGAL_GAMBLING_SUSPECTED"
    MALWARE = "MALWARE"
    OTHER = "OTHER"


class ReviewState(StrEnum):
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    UNKNOWN = "UNKNOWN"


class EvidenceLink(Strict):
    evidence_id: str
    feature: Annotated[str, Field(max_length=64)]
    reason: Annotated[str, Field(max_length=300)]


class ThreatScore(Strict):
    type: ThreatType
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_links: list[EvidenceLink] = []


class ModelMeta(Strict):
    model_version: Str256
    model_hash: Str256
    backend: Str256
    inferred_at: datetime = Field(default_factory=utcnow)


class AIAnalysis(Strict):
    analysis_id: str = Field(default_factory=lambda: new_id("ana"))
    candidate_id: str
    threat_types: list[ThreatScore]
    state: ReviewState
    state_reason: Annotated[str, Field(max_length=300)] = ""
    model_meta: ModelMeta
    # AI 는 판정 권한이 없다. 구조적으로 고정.
    decision_authority: Annotated[str, Field(pattern=r"^NONE$")] = "NONE"


# ─────────────────────────── ③ 평판·검토·감사 ───────────────────────────


class ReputationResult(StrEnum):
    LISTED = "LISTED"
    NOT_LISTED = "NOT_LISTED"  # 미등재는 BENIGN 근거가 아니다
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


class Reputation(Strict):
    provider: Str256
    url: Str2K
    result: ReputationResult
    threats: list[Str256] = []
    detail: Str256 = ""
    checked_at: datetime = Field(default_factory=utcnow)


class Decision(StrEnum):
    THREAT_CONFIRMED = "THREAT_CONFIRMED"
    NOT_THREAT = "NOT_THREAT"
    INCONCLUSIVE = "INCONCLUSIVE"


class Review(Strict):
    candidate_id: str
    reviewer_id: Str256
    decision: Decision
    reason: Annotated[str, Field(min_length=5, max_length=2000)]
    decided_at: datetime = Field(default_factory=utcnow)


class AuditLog(Strict):
    actor: Str256
    action: Str256
    target: Str256
    result: Annotated[str, Field(pattern=r"^(OK|DENIED|ERROR)$")]
    timestamp: datetime = Field(default_factory=utcnow)
    detail: Str256 = ""


# ─────────────────────────── 파이프라인 이벤트(SSE) ───────────────────────────


class Stage(StrEnum):
    DISCOVERY = "DISCOVERY"
    SCREENING = "SCREENING"
    INVESTIGATION = "INVESTIGATION"
    ANALYSIS = "ANALYSIS"
    REPUTATION = "REPUTATION"
    PACKAGE = "PACKAGE"
    REVIEW = "REVIEW"


class StageStatus(StrEnum):
    WAITING = "WAITING"
    RUNNING = "RUNNING"
    DONE = "DONE"
    FAILED = "FAILED"


class PipelineEvent(Strict):
    event_id: int = 0
    type: Annotated[str, Field(pattern=r"^[a-z_.]+$")]
    case_id: str | None = None
    candidate_id: str | None = None
    stage: Stage | None = None
    status: StageStatus | None = None
    ts: datetime = Field(default_factory=utcnow)
    data: dict[str, Any] = {}


class SubmitUrl(Strict):
    url: HttpUrl
    source: SeedSource = SeedSource.REPORT
    note: Annotated[str, Field(max_length=500)] = ""
