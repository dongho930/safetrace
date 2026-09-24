# 03. 데이터 스키마 (설계 확정본 v1.0)

단일 원본: 애플리케이션 모델 `backend/src/safetrace/schemas.py`(Pydantic, `extra="forbid"`), DB DDL `infra/db/schema.sql`(PostgreSQL 18). 둘은 필드 단위로 대응한다.

## 1. 객체 관계

```
Case 1─* Candidate ─┬─1 Observation
         │  ▲       ├─* Evidence (전역 seq 해시 체인)
         │  └ discovered_from (관계 그래프, candidate_edge)
         │          ├─1 AIAnalysis ── evidence_links → Evidence.evidence_id
         │          ├─* Reputation
         │          └─0..1 Review (reviewer 만)
AuditLog (추가 전용, 모든 상태 전이·거부)
```

## 2. 객체별 핵심 필드(기획서 2.5 확장)

| 객체 | 필드 | 제약 |
|---|---|---|
| Case | case_id, source, original_url, submitted_by, created_at | source ∈ KISA·REPORT·SEARCH_API |
| Candidate | candidate_id, case_id, source, original_url, normalized_url, registrable_domain, discovered_from, relation, depth, priority, score_reasons[], status, status_reason, idempotency_key, created_at | (case_id, idempotency_key) 유일 = 사건 visited 집합, depth 0~5 |
| Observation | final_url, reachable, redirect_chain[{url,status,kind}], dom_summary, forms[], request_summary, observed_links[], popups/downloads_blocked, policy_blocks[], errors[], agent_version | 문자열 길이 상한(2048/4000) |
| Evidence | evidence_id, seq, case_id, candidate_id, type, object_path, sha256, size, captured_at, version, prev_hash, record_hash, hmac_sig, key_id | 추가 전용, sha256 hex 검사 |
| AIAnalysis | analysis_id, candidate_id, threat_types[{type, confidence, evidence_links[]}], state, state_reason, model_meta{model_version, model_hash, backend, inferred_at}, decision_authority="NONE" | confidence 0~1, state ∈ REVIEW_REQUIRED·UNKNOWN |
| Reputation | provider, url, result, threats[], detail, checked_at | result ∈ LISTED·NOT_LISTED·ERROR·SKIPPED |
| Review | candidate_id, reviewer_id, decision, reason, decided_at | reason 5~2000자, DB 트리거로 reviewer 역할만 |
| AuditLog | actor, action, target, result, detail, timestamp | 추가 전용 |

## 3. 후보 상태 머신

```
DISCOVERED → SCREENING → QUEUED → INVESTIGATING → ANALYZING → PACKAGING → REVIEW_REQUIRED → DECIDED
                 │                     │
                 ├→ BLOCKED(IP_NOT_PUBLIC·URL_*)     ├→ UNREACHABLE(접속 불가)
                 └→ UNREACHABLE(DNS_*)               ├→ BLOCKED(리다이렉트가 금지 대상)
                                                      └→ FAILED(LEASE_TIMEOUT·RESULT_MISMATCH·ARTIFACT_REJECTED)
발굴 단계 제외: SKIPPED(DUPLICATE·ALLOWLISTED·LOW_PRIORITY·*_BUDGET·DEPTH_LIMIT) — 재큐잉 결과 집계로만 기록
```

## 4. 증거 레코드 해시(정규화 규칙)

```
record_hash = SHA256( JSON(sort_keys, separators=(",",":"), ensure_ascii) of
  {seq, evidence_id, case_id, candidate_id, type, object_path, sha256, size, captured_at(ISO8601 UTC), version, prev_hash} )
hmac_sig    = HMAC-SHA256(K_signer, "safetrace.evidence.v1|{seq}|{record_hash}")
prev_hash(1) = "0"*64
```

검증(`EvidenceLedger.verify`) 코드: `RECORD_DELETED`(seq 공백), `CHAIN_BROKEN`(prev_hash 불일치), `RECORD_MODIFIED`(재계산 불일치), `SIGNATURE_INVALID`, `OBJECT_MODIFIED`, `OBJECT_MISSING`, `TAIL_TRUNCATED`(서명 서비스 high-water mark > 원장 끝), `HEAD_MISMATCH`.

## 5. 파이프라인 이벤트(SSE)

`PipelineEvent{event_id, type, case_id, candidate_id, stage, status, ts, data}`

| type | data | 재생(Last-Event-ID) |
|---|---|---|
| candidate.discovered | url, source, priority, depth, from, relation | ✅ |
| candidate.status | from, to, reason, url, priority, depth | ✅ |
| evidence.stored | evidence_id, type, sha256, seq | ✅ |
| analysis.done | state, top[{type, confidence}] | ✅ |
| reputation.done | results[] | ✅ |
| discovery.expanded | queued, skipped{사유:건수}, impersonates[] | ✅ |
| investigation.step | step(navigate·rendered·collected), 값 | ✅ |
| investigation.frame | jpeg_b64(≤400KB) | ❌(최신 프레임만) |
| pipeline.stats | discovered, waiting, investigating, review_required, decided, failed, skipped, cases | ✅ |

## 6. 증거 파일 저장 규칙

- 경로: `objects/<case_id>/<evidence_id><고정 확장자>` — ID 는 서버 생성값만(영숫자·`_`), 원본 파일명 미사용.
- 수집 HTML 은 `.html.txt` 로 저장하고 `text/plain` 첨부로만 제공한다(콘솔에서 렌더링 금지).
- 기존 파일 덮어쓰기 금지(`open(..., "xb")`).
