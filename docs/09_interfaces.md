# 09. 핵심 인터페이스 (설계 확정본 v1.0)

모든 요청·응답 본문은 JSON(Pydantic 검증, 알 수 없는 필드 거부). 오류는 `{"error": "<CODE>"}` 또는 FastAPI 검증 오류(422)만 반환한다.

## 1. 콘솔 API (`Authorization: Bearer <token>`)

| 메서드·경로 | 역할 | 요청 | 응답 |
|---|---|---|---|
| GET `/api/me` | 전체 | – | `{user_id, role}` |
| POST `/api/cases` | investigator·reviewer·automation | `{url, source?, note?}` | 201 `{case_id, candidate_id, normalized_url}` / 400 `URL_*` |
| POST `/api/seeds/kisa?limit=1..200` | 〃 | CSV 본문(≤20MB) | `{loaded, rejected, duplicates, submitted}` |
| GET `/api/stats` | 전체 | – | `{discovered, waiting, investigating, review_required, decided, failed, skipped, cases}` |
| GET `/api/candidates` | 전체 | – | 후보 요약 배열(최신 500) |
| GET `/api/candidates/{id}` | 전체 | – | `{candidate, observation, analysis, reputation[], review, evidence[], impersonates[]}` |
| GET `/api/candidates/{id}/package` | 전체(감사로그 기록) | – | 검토 패키지 JSON(integrity 재검증 포함) |
| POST `/api/candidates/{id}/review` | **reviewer 만** | `{decision, reason(5~2000)}` | Review / 403 `FORBIDDEN_ROLE` / 409 `INVALID_STATE` |
| GET `/api/evidence/verify` | 전체 | – | ChainVerification |
| GET `/api/evidence/{evidence_id}/content` | 전체 | – | 원본(재검증 후). PNG·WebM inline, HTML·JSON attachment / 409 `EVIDENCE_TAMPERED` |
| GET `/api/graph` | 전체 | – | `{nodes[], edges[]}` |
| GET `/api/audit` | reviewer | – | 감사로그 최근 500 |
| GET `/api/events` | 전체 | 헤더 `Last-Event-ID` | `text/event-stream` (03 문서 §5) |

## 2. 수집 API (Worker 전용, ingest-gw 경유)

헤더: `Authorization: Bearer <SAFETRACE_WORKER_TOKEN>`, `X-Worker-Id: [A-Za-z0-9_-]{1,64}`

| 메서드·경로 | 요청 | 응답 |
|---|---|---|
| POST `/ingest/v1/lease` | `{worker_id}` | 200 `{job_id, candidate_id, url}` / 204(작업 없음, 최대 20초 대기) |
| POST `/ingest/v1/jobs/{job_id}/frame` | JPEG ≤ 400KB | 204 |
| POST `/ingest/v1/jobs/{job_id}/step` | `{step:[a-z_]{1,32}, data{}}` | 204 |
| POST `/ingest/v1/jobs/{job_id}/artifact/{SCREENSHOT|HTML|VIDEO|HAR}` | 바이너리(유형별 상한) | 204 |
| POST `/ingest/v1/jobs/{job_id}/result` | Observation JSON(≤2MB) | 204 — 서버가 OBSERVATION 증거를 직접 생성 |
| POST `/ingest/v1/jobs/{job_id}/fail` | `{code:[A-Z0-9_]{1,64}}` | 204 |

lease 는 job_id·worker_id·candidate_id 가 모두 일치해야 결과를 받는다(`JOB_NOT_FOUND`, `RESULT_MISMATCH`).

## 3. 서명 서비스 (signer, svc 망 내부)

헤더 `Authorization: Bearer <SAFETRACE_SIGNER_TOKEN>`

| 경로 | 요청 | 응답 |
|---|---|---|
| POST `/v1/sign` | `{seq, record_hash}` | `{sig, key_id}` / 409(seq 재서명·건너뛰기) |
| POST `/v1/verify` | `{seq, record_hash, sig, key_id}` | `{valid}` |
| GET `/v1/head` | – | `{max_seq, head_hash}` |

## 4. 내부 Python 인터페이스

| 인터페이스 | 시그니처 | 교체 가능 구현 |
|---|---|---|
| `UrlPolicy.check_url` | `async (raw) -> (NormalizedUrl, ips)` / `PolicyViolation(code)` | – |
| `BrowserAgent.investigate` | `async (candidate_id, url, on_frame?, on_step?) -> AgentResult{observation, artifacts}` | HAR 재생 모드 |
| `DecisionEngine.analyze` | `(Observation, {EvidenceType: evidence_id}) -> AIAnalysis` | `TextClassifier` 프로토콜(로컬 제로샷, 향후 Jev) |
| `Frontier.expand` | `(parent, Observation, age_lookup?) -> ExpandResult{queued, impersonates, skipped}` | RDAP `DomainAgeLookup` |
| `EvidenceLedger.append/verify` | `async (...) -> Evidence` / `async (candidate_id?) -> ChainVerification` | PostgreSQL 저장소(1주차) |
| `JobSource` | lease·frame·step·complete·fail | `HttpJobSource`(격리), `LocalJobSource`(개발) |
| `EventBus.publish/subscribe` | Redis Streams 와 동일 의미 | Redis Streams(1주차) |
| `SafeBrowsingClient.lookup` | `async (urls) -> [Reputation]` | 추가 평판 Connector |

## 5. 큐 메시지(1주차 Redis Streams 확정 형식)

```
st:jobs    {candidate_id, case_id, url, priority, depth, idempotency_key, enqueued_at}
st:events  PipelineEvent JSON (필드 1개: data)
consumer group: workers / console-sse
멱등: 결과 처리 전 candidate.status == INVESTIGATING AND lease 일치 확인, 중복 결과는 무시
```
