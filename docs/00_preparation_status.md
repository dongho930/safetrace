# 00. 사전준비 점검표 (기획서 2.9 「사전준비(~10/5) 기구현 + 설계 확정」)

점검일: 2026-09-24 · 엔진 st-rules-1.1 · 전체 시험 **112 passed**(단위·보안 101 + 실제 Chromium 통합 11)
정적 점검: ruff 0 · Bandit 0 · pip-audit 알려진 취약점 0 · npm audit 0 · 프론트 `tsc -b` + `vite build` 통과

## 1. 기구현 항목

| 기획서 항목 | 산출물 | 검증 | 상태 |
|---|---|---|---|
| 브라우저 렌더링 녹화 | `agent/browser.py` (WebM 녹화 → VIDEO 증거) | `test_delayed_rendering_captured_with_evidence`(EBML 헤더), 컨테이너 조사에서 VIDEO 증거 서명 확인 | ✅ |
| 실시간 조사 화면 | CDP screencast(2fps) → `investigation.frame` SSE → `LiveView` | 브라우저 자동 시연(콘솔 오류 0) | ✅ |
| AI 분석 의견 생성 | `ai/engine.py` 규칙 특징 + 선택적 로컬 제로샷 | `test_ai_engine`(10), D1-S Macro-F1 0.977 | ✅ (제로샷 실물 검증 완료 → 규칙 전용 기본 유지, 아래 §5) |
| Safe Browsing 조회 | `reputation/safebrowsing.py` (v4 Lookup, 미등재≠정상, 실패 시 ERROR 후 계속) | `test_safebrowsing_*`(Mock), 실키 조회(2026-09-24): Google 시험 URL phishing→LISTED(SOCIAL_ENGINEERING)·malware→LISTED(MALWARE)·google.com→NOT_LISTED | ✅ |
| 공개 정상 사이트 평가 자료(D3) | `data/d3/benign_sites.csv` 184개 + `tools/eval/run_d3.py` | 1차 측정: 도달 167, UNKNOWN 85%, 고신뢰 경보 5, 자동 확정 0 | ✅ |

## 2. 10/5 까지 구현 항목

| 기획서 항목 | 산출물 | 검증 | 상태 |
|---|---|---|---|
| 파이프라인 실시간 UI(SSE, 단계별 대기·진행·완료·실패, 발견·대기·조사·검토 건수) | `frontend/` (PipelineStrip·후보 목록·관계 그래프·이벤트·상세·판정), `/api/events`(Last-Event-ID 재생) | `test_event_bus_replay_and_stats`, 브라우저 자동 시연 | ✅ |
| AI Decision Engine 1차(특징 추출·규칙+제로샷 결합·구조화 출력·UNKNOWN 정책) | `ai/features.py`·`rules.py`·`zeroshot.py`·`engine.py` | 스키마 강제(`decision_authority=NONE`), 프롬프트 인젝션 시험 | ✅ |
| 조사 Worker 전용 네트워크(Docker internal)·egress 프록시 | `infra/docker-compose.yml`, `proxy/egress.py`, `infra/ingest-gw` | **컨테이너 내부 격리 검증 12/12 통과**, 프록시 거부 9종·DNS Rebinding 시험 | ✅ |
| 증거 해시 체인(직전 레코드 해시 연결·추가 전용 저장) | `evidence/ledger.py`, `infra/db/schema.sql` 트리거 | `test_evidence_chain` 13종 | ✅ |
| 해시 체인에 분리된 서명 서비스의 HMAC 서명 | `signer/app.py`(키 단독 보유, seq 재서명 금지, high-water mark) | 체인 재작성·끝 레코드 삭제 탐지, 컨테이너에서 서명·검증 확인 | ✅ |
| 기구현 브라우저 모듈에 URL·DNS·IP 재검증·리다이렉트 추적 통합 | `_route`/`_route_document`(hop 마다 재검사) | `test_redirect_to_private_ip_blocked`(사설·메타데이터·루프백), 루프 제한 | ✅ |
| D1-R 실데이터 수집 가동(2주차까지 매일) | `tools/collect/d1r_collect.py`, compose `collector` 프로필, HAR 재생 평가기 | HAR 재생 오프라인 재현 시험 | ✅ **가동 중(2026-09-25~)** — 아래 §5 |

## 3. 설계 확정 항목

| 기획서 항목 | 문서 |
|---|---|
| 요구사항·범위 | [01_requirements_scope.md](01_requirements_scope.md) |
| 아키텍처 | [02_architecture.md](02_architecture.md) |
| 데이터 스키마 | [03_data_schema.md](03_data_schema.md), `backend/src/safetrace/schemas.py`, `infra/db/schema.sql` |
| 위협 모델 | [04_threat_model.md](04_threat_model.md) (STRIDE + D2 15종 ↔ 시험 매핑) |
| Candidate Discovery 정책·후보 스키마 | [05_candidate_discovery_policy.md](05_candidate_discovery_policy.md) |
| KISA 데이터 적재 형식 | [06_kisa_data_format.md](06_kisa_data_format.md) |
| 개발환경·저장소·CI | [07_dev_env_ci.md](07_dev_env_ci.md), `.github/workflows/ci.yml`, `.semgrep/safetrace.yml` |
| 평가셋·보안 시험 시나리오 | [08_evaluation_plan.md](08_evaluation_plan.md), `data/d1s`, `data/d3`, `data/d4` |
| 핵심 인터페이스 | [09_interfaces.md](09_interfaces.md) |

## 4. 사전준비 통과 기준(기획서 2.9) 대조

| 통과 기준 | 결과 |
|---|---|
| 기구현 기능 동작 확인 | ✅ 로컬·컨테이너 양쪽에서 조사→증거→AI→평판→검토 흐름 확인 |
| 실시간 UI 에 조사 흐름의 단계별 상태 표시 | ✅ 8단계 스트립 + 6개 건수 타일 + 이벤트 로그 |
| AI 엔진이 샘플 증거 입력에 유형·confidence·UNKNOWN 을 구조화 출력으로 반환 | ✅ |
| Worker 의 내부 서비스 직접 접속 차단 확인 | ✅ api·signer·postgres·redis·메타데이터·직접 인터넷 모두 차단 |
| 증거 레코드 수정·삭제 시 해시 체인·HMAC 검증 실패 확인 | ✅ |
| 사설·예약 IP 로 향하는 리다이렉트 차단 확인 | ✅ |
| 개발환경 재현 가능 | ✅ lockfile + `docker compose build` 무에서 재빌드 확인 |
| Seed 소스·후보 큐·우선순위·탐색 한도와 핵심 인터페이스·스키마·위협 모델 확정 | ✅ 문서 01~09 |

## 5. 남은 일·팀 결정이 필요한 항목

| 항목 | 필요한 조치 | 기한 |
|---|---|---|
| D1-R 수집 가동 | **가동 시작(2026-09-25)**: 이용 조건 확인(OpenPhish 커뮤니티=비상업 연구 허용·재배포 금지, URLhaus=fair use 무료) → `collector` 컨테이너 매일 1회(60건/일, `restart: unless-stopped`). 첫 라운드 누적: 수집 67(OpenPhish 50·URLhaus 17), 접속 불가 50, 약 91MB. HAR 재생 평가 동작 확인(`replay_d1r.py`, 스모크 4건 전부 UNKNOWN — 영문 지갑 피싱, 한국어 규칙 한계). 수정: OpenPhish 피드가 GitHub로 302 이동 → URL 교체·리다이렉트 허용, 피드 번갈아 뽑기(URLhaus IoT URL 독점 방지). **남은 일**: PC·Docker Desktop이 켜져 있어야 매일 수집됨, 2인 교차 라벨링은 웹콘솔 **D1-R 라벨링** 탭(표본 50%, 블라인드, 불일치는 합의 라벨, κ 자동 계산 — [10_labeling_guide.md](10_labeling_guide.md)), 10/18 동결 | 10/18 동결 |
| ~~Safe Browsing 실키~~ | ✅ 2026-09-24 `.env` 설정·실조회 확인 완료 | — |
| 네이버 검색 API | **소스 확정(2026-09-25)**: 구글 Custom Search는 신규 가입 불가·2027-01-01 종료, SERP API는 스크래핑이라 제외 → 네이버 웹문서 검색. **발급처 변경**: 신규 신청은 개발자센터가 아니라 네이버 클라우드 플랫폼 **NAVER API HUB**(현재 한시 무료, 검색 합산 월 775,000회·키당 50 RPS, 초과 시 429). 엔드포인트 `naverapihub.apigw.ntruss.com/search/v1/webkr`, 헤더 `X-NCP-APIGW-API-KEY-ID`/`X-NCP-APIGW-API-KEY`— **실키 호출 확인(2026-09-25)**: 200, 응답 스키마는 기존과 동일(`total/start/display/items[title,link,description]`), 단 Content-Type 이 `text/plain` 이라 JSON 직접 파싱 필요. 시험 질의 "택배 주소 확인" 상위 5건은 법령정보·뉴스·지자체 공지로 피싱 사이트 0건(예상한 한계). 설정 `SAFETRACE_NAVER_CLIENT_ID/SECRET`. **남은 일**: 1주차 연동 후 사칭 키워드 약 100건 적중률 측정 → 낮으면 소스 제외 보고 | 1주차 |
| 로컬 제로샷 모델 | **검증 완료(2026-09-25), 결론: 기본값은 규칙 전용 유지(제로샷 미채택)**. `[ai]` 설치(torch 2.14·transformers 5.17, Py3.14 동작), 모델 리비전 `b5113eb` 고정, 로드 24s·분류 약 2.5s/건(CPU). D1-S(`reports/d1s_eval_zs.json`): 판정 변화 0건, Macro-F1 0.977 동일, BENIGN 평균 신뢰도 0.12→0.33. D3 정상 167곳(`reports/d3_eval_zs.json`): REVIEW_REQUIRED 26→36(15.6%→21.6%, 오탐 +10), 고신뢰(≥0.8) 경보 5→3. 상태 변화 18곳(UNKNOWN→REVIEW 14: 은행·카드·언론·SRT 등, 반대 4). 원인: 제로샷이 정상 페이지에도 PHISHING/MALWARE 0.3~0.5를 주어 ZS_BLEND 0.35로 섞으면 UNKNOWN_BELOW 0.45 근처로 몰림. → 이득은 없고 오탐만 늘어서 `--zeroshot`은 실험용 옵션으로만 둔다. 컨테이너 이미지 반영 불필요. 재검토 조건: 한국어 피싱 라벨 데이터로 미세조정했거나 ZS_BLEND≤0.15 재평가 | 10/5 ✅ |
| CI 실행 | **완료(2026-09-25)**: PR #1(`prep/pre-contest-setup`)에서 backend(ruff·pytest 단위+브라우저·bandit·pip-audit)·frontend·semgrep·gitleaks 4개 잡 전부 통과. 첫 실행 실패 2건 수정: 액션을 커밋 SHA로 고정(semgrep 공급망 규칙), secrets 잡에 `pull-requests: read` 부여(gitleaks 403). PR #1 main 병합 완료 | 10/5 ✅ |
| D3 오탐 개선 | 허용목록 Tranco·금융기관 병합, D1-R 라벨 후 가중치 보정 | 2주차 |
| 인메모리 → PostgreSQL·Redis Streams | 02 문서 §5 교체 계획 | 1주차 |

## 6. 점검 중 발견·수정한 결함

| 발견 | 원인 | 조치 |
|---|---|---|
| 3단계 리다이렉트 중 첫 hop 만 정책 검사를 거침 | Chromium 이 넘겨받은 3xx 의 후속 hop 을 route 없이 내부에서 따라감 | 문서 3xx 를 브라우저에 넘기지 않고 Location 검사 후 meta refresh 로 새 탐색 → hop 마다 재검사(`test_http_redirect_chain_recorded`) |
| 조사 대상 페이지 자체가 팝업으로 오인되어 닫힘 | async API 의 `page.opener()` 가 코루틴 | `await page.opener()` 로 수정 |
| 이미 거쳐 간 리다이렉트 hop 이 재큐잉되어 중복 조사 | 관찰 링크에 체인 hop 포함 | 부모 체인 URL 을 visited 로 선반영, 타 도메인 경유는 TRAVERSED 관계로만 기록 |
| D3 공공 사이트 오탐(8개 중 5개) | 공식 도메인의 기관명·환급 문구를 사칭 근거로 사용 | `domain_official` 감점(사용자 콘텐츠 호스트 제외), 규칙 1.1 |
| 평가 시 모든 페이지가 IP 호스트 특징으로 오염 | 시험 사이트를 127.0.0.1 로 제공 | 평가·개발 시험 사이트를 `localhost` 로 제공 |
| Worker 이미지 Python 3.12 | Playwright 공식 이미지 기본 버전 | `python:3.13-slim` + `playwright install --with-deps` 로 교체 |
| 근로복지공단(comwel.or.kr)이 유사 도메인으로 판정(D3 경보 분석 중 발견) | 허용목록에 `kcomwel.or.kr` 오기 → 실제 도메인이 편집 거리 1의 '사칭'으로 판정 | `comwel.or.kr` 로 수정, `test_d3_official_sites_are_allowlisted_not_lookalikes` 추가 |
