# 08. 평가 설계 — 데이터·지표·통과 기준 (설계 확정본 v1.0) + 사전 측정값

원칙(기획서 2.11): 요구사항 → 데이터 → 지표 → 통과 기준을 사전에 고정하고, 목표 미달이어도 **실측값을 그대로 보고**한다. 실제 위협 URL 접속은 D1-R 수집과 D4 Seed 조사로만 한정한다.

## 1. 평가 데이터

| 세트 | 구성(확정) | 위치 | 상태(2026-09-24) |
|---|---|---|---|
| D1-R 실제 위협 스냅샷 | OpenPhish 커뮤니티·URLhaus·KISA URL 중 수집 시점 접속 가능 URL 을 격리 환경에서 **1회** 수집(HAR·스크린샷·DOM·관찰 JSON + SHA-256)·동결, 표본 50% 2인 교차 라벨링(블라인드, 불일치는 합의 라벨, κ 보고 — [10](10_labeling_guide.md)), 주차·삭제·판단 불가 제외. 건수는 사전에 정하지 않고 실측 보고 | `tools/collect/d1r_collect.py` → `data/d1r/`(커밋 제외), 평가 `tools/eval/replay_d1r.py`(HAR 재생) | 수집기·재생기 구현, compose `collector` 프로필로 매일 수집 → **10/18 동결** |
| D1-S 합성 시험 페이지 | 피싱·사기·도박 의심 각 20 + 정상 대조 30 = 90. 변형: plain·delayed(1.5초 뒤 삽입)·redirect(HTTP 2~3단계)·jsredirect(meta/JS) | `data/d1s/generate.py`(결정적, d1s-1.0), `labels.csv` | **생성·측정 완료** |
| D2 공격 시나리오 | 15종(04 문서 §3) | `backend/tests/*`, `infra/scripts/verify_isolation.py` | 자동 시험 구현 |
| D3 공개 정상 사이트 | 공공 67·금융 46·쇼핑 30·택배 12·포털/언론/기타 29 = **184**, 첫 화면 1회 렌더링, 요청 간격 ≥4~5초 | `data/d3/benign_sites.csv`, `tools/eval/run_d3.py` | **목록 확정·1차 측정 완료** |
| D4 자율 후보 발굴 | Seed 10 + 설계된 연관 후보 50(깊이1 40·깊이2 10) + 함정(허용목록·CDN·순환·중복·도메인 잡음 링크) | `data/d4/generate.py`, `graph.json`(정답 키) | 시험군·정답 키 확정, 하네스(시험 전용 프록시로 `*.test`→로컬) 3주차 |

## 2. 지표·통과 기준

| 지표 | 목표 | 측정 방법 |
|---|---|---|
| R1 동적 증거 포착 | D1-S 회피 변형의 핵심 징후 ≥ 90% | 정적 HTML 기준선과 비교(`run_d1s.py`) |
| R2 증거 무결성 | 메타데이터 포함률 100%, 변조 탐지 100% | 파일 단독·파일+해시·레코드 해시 재계산·중간/끝 삭제·체인 재작성 주입(`test_evidence_chain`) |
| R3 AI 분석 품질 | 유형별 Macro-F1 ≥ 0.80(목표), confidence·UNKNOWN 함께 보고 | 피싱·악성 D1-R(HAR 재생), 사기·도박 D1-S 보완, 출처별 구분, 모델 버전 고정 |
| R4 설명가능성 | evidence_links 제시율 100% | 결과 JSON 자동 검사 |
| R5 안전성 | D2 15종 모두 차단/격리 | 자동·수동 보안 시험 |
| R6 처리시간 | 수동 대비 사건당 50% 이상 단축 | 기준 절차 vs SafeTrace, 팀 외 사용자 4~6명(3주차) |
| R7 정상 오인 | AI·자동화 계정에 의한 위협 판정 자동 확정 0건 | D1-R·D1-S 정상 대조·D3. 보조 지표로 REVIEW_REQUIRED 비율·고신뢰(≥0.8) 경보 수 보고 |
| R8 자율 발굴 | 설계 후보 50 중 40(80%) 이상, 허용목록 재큐잉·예산 초과·중복 조사 0 | 발견 경로·깊이 로그 자동 검사(`graph.json`) |

## 3. 사전 측정값(엔진 st-rules-1.1, 2026-09-24, 로컬 Windows 환경)

### D1-S (`reports/d1s_eval.json`, n=90)

| 지표 | 동적(SafeTrace) | 정적 HTML 기준선 |
|---|---|---|
| R1 회피 변형 핵심 징후 포착(n=45) | **100%** | 55.6% |
| 최종 URL 도달 | 100% | – |
| R3 Macro-F1(피싱·사기·도박) | **0.977** (피싱 0.930, 사기 1.000, 도박 1.000) | 0.794 |
| 정상 30 → UNKNOWN / REVIEW_REQUIRED | 27 / 3 (정상 로그인 폼 대조 페이지) | – |
| R4 evidence_links 제시율 | **100%** | – |

해석 주의: D1-S 는 규칙을 만든 팀이 설계한 합성 데이터이므로 **일반화 성능이 아니다**. R3 의 공식 값은 D1-R 에서 측정한다. D1-S 는 회피 변형(지연 렌더링·리다이렉트)에서 동적 수집이 정적 분석보다 무엇을 더 보는지(R1)를 보이는 용도다.

### D3 (`reports/d3_eval.json`, n=184)

| 항목 | 값 |
|---|---|
| 도달(본문 확보) | 167 / 184 (미도달 17: 봇 차단·JS 전용 첫 화면·타임아웃 — 실측 그대로 보고) |
| UNKNOWN(보류) | 142 (85.0%) |
| REVIEW_REQUIRED | 25 (15.0%) — 금융 10, 포털·언론 7, 쇼핑 4, 공공 2, 택배 2 |
| 고신뢰(≥0.8) 경보 | 5 |
| **자동 확정(R7)** | **0** (구조적 보장: `decision_authority=NONE`, RBAC, DB 트리거) |
| 경보 주요 특징 | kw_impersonation 20, kw_money_request 15, kw_scam_investment 15, kw_urgency 11, form_password 7 |

개선 이력: 첫 8개 공공 사이트 표본에서 규칙 1.0 은 5/8 을 REVIEW_REQUIRED(홈택스 0.96)로 올렸다. 공식 도메인에서의 기관명·환급 문구는 사칭 근거가 아니므로 `domain_official` 감점(사용자 콘텐츠 호스트 제외)을 추가해 1.1 로 올렸고, D1-S 결과는 변하지 않았다(회귀 없음).

남은 오탐 원인과 계획: 허용목록에 없는 금융·보험·증권사 첫 화면의 "투자·수익률·보장·결제" 문구. → 2주차 Tranco 상위 + 금융기관 공식 도메인 목록 병합(`allowlist.txt`), 키워드 가중치는 D1-R 라벨이 확보된 뒤에만 보정(과적합 방지). 보정 전후 값을 함께 보고한다.

## 4. 재현 방법

```powershell
.venv\Scripts\python data\d1s\generate.py; .venv\Scripts\python tools\eval\run_d1s.py
.venv\Scripts\python tools\eval\run_d3.py --interval 5
docker compose --env-file .env -f infra\docker-compose.yml --profile collector up -d collector   # D1-R
.venv\Scripts\python tools\eval\replay_d1r.py --root data\d1r --labels data\d1r\labels.csv
```

평가셋 버전(d1s-1.0·d3-1.0·d4-1.0)과 엔진 버전(`model_meta.model_version`, 규칙 해시)을 결과 파일에 함께 기록한다.
