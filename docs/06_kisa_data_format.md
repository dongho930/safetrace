# 06. KISA 피싱사이트 URL 적재 형식 (설계 확정본 v1.0)

대상 데이터: 공공데이터포털 「한국인터넷진흥원_피싱사이트 URL」(파일데이터 CSV, 오픈 API). 구현: `backend/src/safetrace/ingest/kisa.py`.

## 1. 입력

| 형식 | 필드 | 인코딩 |
|---|---|---|
| CSV | `날짜`, `홈페이지주소` (별칭 허용: URL·url·홈페이지 주소·피싱사이트 / 등록일·date·탐지일) | UTF-8, UTF-8-SIG, CP949 자동 판별 |
| 오픈 API(JSON) | `{"page","perPage","totalCount","data":[{"날짜","홈페이지주소"}]}` | UTF-8 |

날짜 형식: `YYYY-MM-DD`, `YYYY.MM.DD`, `YYYYMMDD`, `YYYY/MM/DD` (해석 실패 시 null).

## 2. 정규화·검증 규칙

1. 앞뒤 공백·따옴표·내부 공백 제거
2. 스킴이 없으면 `http://` 부여(원문은 `original` 에 보존)
3. `normalize_url`: 스킴 http/https, userinfo 금지, 위험 포트 거부, IDN→punycode, 소문자 호스트, fragment 제거
4. IP 리터럴이면 공개 대역만 허용
5. 정규화 URL 의 SHA-256 을 `idempotency_key` 로 파일 내 중복 제거
6. 최대 200,000행

## 3. 출력

`KisaLoadResult{records[KisaRecord{original, normalized_url, registrable_domain, idempotency_key, detected_on}], rejected[(원문 앞 200자, 사유 코드)], duplicates}`

거부 사유 코드: `EMPTY_URL`, `URL_*`(정규화 실패), `IP_NOT_PUBLIC`, `MAX_ROWS_EXCEEDED`.

## 4. 적재 흐름

`POST /api/seeds/kisa?limit=N` (본문: CSV, 20MB 이하) → 정규화 결과 중 상위 N개를 `SeedSource.KISA` 로 접수 → 접근 전 검사.
운영 시에는 1주차에 `candidate` 테이블 일괄 적재 + 우선순위 큐 순차 투입으로 바꾸고, 과거 탐지 URL 의 접속 불가는 `UNREACHABLE` 로 집계해 실제 건수를 보고한다.

## 5. 참조 데이터 활용

KISA URL 은 Seed 이자 URL·도메인 패턴 참조 데이터다. 2주차에 도메인 TLD·길이·하이픈·브랜드 결합 분포를 집계해 `SUSPICIOUS_TLDS`·키워드 사전 보정에 쓰되, 보정 전후 D1-S/D3 결과를 함께 보고한다.
