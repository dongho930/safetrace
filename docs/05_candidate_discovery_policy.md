# 05. Candidate Discovery 정책·후보 스키마 (설계 확정본 v1.0)

구현: `backend/src/safetrace/discovery/{policy,allowlist,similarity}.py`

## 1. Seed 소스

| 소스 | 형식 | 초기 우선순위 | 제약 |
|---|---|---|---|
| REPORT 신고 URL | 단건 API·CSV | 10 | 담당자·자동화 계정 접수 |
| KISA 피싱사이트 URL | 공공데이터포털 CSV·오픈 API(06 문서) | 8 | 과거 탐지 URL 은 UNREACHABLE 이 많음 → 별도 상태 기록 |
| SEARCH_API | 네이버 검색 API(웹문서) 공식 응답 | 6 | KISA·보호나라 주의보의 사칭 키워드만, 일 25,000회 이내, 검색 결과 페이지 스크래핑 금지. 약관 제약 시 이 소스만 제외 |
| DISCOVERED | 조사 중 관찰된 연결 | 점수식 | 아래 §3 |

## 2. 후보 추출(관찰 → ObservedLink)

| 관계 | 추출 위치 |
|---|---|
| REDIRECT | 문서 HTTP 3xx hop, meta refresh, JS 이동으로 바뀐 최상위 URL |
| FORM_ACTION | `<form action>` (없으면 현재 URL) |
| LINK | `<a href>` (javascript: 등 비HTTP 제외, 300개 상한) |
| SCRIPT | `<script src>` |
| RESOURCE | `<iframe src>`, `<img src>`, `<link rel=stylesheet/preload/icon>` |

## 3. 재큐잉 규칙(순서대로 적용)

1. **정규화 실패** → 제외(`INVALID_URL`)
2. **허용목록**(공공·금융·주요 서비스 공식 도메인 + `*.go.kr`, `*.mil.kr`, 운영 시 Tranco 상위 병합) → 재큐잉하지 않고 `IMPERSONATES` 관계로만 기록(사칭 대상 자체가 증거)
3. **visited**(사건 내 정규화 URL 해시) → 제외(`DUPLICATE`). 같은 URL 이 여러 관계로 보이면 최고 점수 관계 하나만
4. **점수화**

| 코드 | 가중치 | 근거 |
|---|---|---|
| REL_REDIRECT / REL_FORM_ACTION | +3.0 | 사용자·데이터가 실제로 이동하는 곳 |
| REL_LINK | +1.0 | |
| REL_SCRIPT | +0.5 | 피싱 키트 호스팅 |
| REL_RESOURCE | +0.3 | |
| LOOKALIKE | +3.0 | 허용목록 브랜드와 skeleton 동일·편집 거리 1·브랜드 결합(combosquatting)·Punycode |
| NEWLY_REGISTERED | +2.0 | RDAP 등록일 ≤ 90일(2주차 연동, 조회 실패 시 가점 없음) |
| FROM_SENSITIVE_FORM_PAGE | +1.5 | 부모 페이지에 비밀번호·카드·주민번호 입력 폼 |
| SUSPICIOUS_TLD / PUNYCODE | +1.0 | |
| COMMON_INFRA | −3.0 | 공용 CDN·광고·분석 도메인 |
| SAME_SITE_LINK | −1.0 | 같은 등록 도메인 내부 일반 링크 |
| DEPTH | −0.5 × depth | 깊을수록 감점 |

5. **임계값** priority < 1.0 → 제외(`LOW_PRIORITY`)
6. **예산**(점수 내림차순으로 채움): 깊이 ≤ 2(`DEPTH_LIMIT`), 사건당 후보 ≤ 30(`CASE_BUDGET`), 등록 도메인당 ≤ 5(`DOMAIN_BUDGET`), 사건 시간 600초

제외 사유는 `discovery.expanded` 이벤트의 `skipped{사유: 건수}` 로 UI·감사에 남는다.

## 4. 후보 스키마(Candidate)

`schemas.Candidate` / `infra/db/schema.sql candidate` 참조. 핵심: `source`, `discovered_from`, `relation`, `depth`, `priority`, `score_reasons[{code, weight, detail}]`, `idempotency_key = SHA256(normalized_url)`, `status`.

## 5. 우선순위 큐

- 사전준비: `asyncio.PriorityQueue((-priority, 삽입순, candidate_id))`
- 1주차: Redis Streams `st:jobs` + PostgreSQL `candidate_queue_idx (status='QUEUED', priority DESC)`. 임대 만료(180초)는 FAILED(LEASE_TIMEOUT) 후 재시도 정책(최대 1회)으로 관리.

## 6. 통과 기준(R8, D4)

설계된 연관 후보 50개 중 40개 이상 발굴, 허용목록 도메인 재큐잉 0, 예산 초과 0, 중복 조사 0 — `data/d4/graph.json` 정답 키로 자동 검사(3주차).
