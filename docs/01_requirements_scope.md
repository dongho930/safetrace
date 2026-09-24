# 01. 요구사항·범위 (설계 확정본 v1.0, 2026-10-05 동결)

기준 문서: `SafeTrace_개발기획서.pdf` 1.4 개발 목표, 2.9 일정, 2.10 범위 통제, 3.5 운영 원칙.
이 문서가 바뀌면 PR 설명에 변경 사유와 영향 받는 시험(R·D2 번호)을 적는다.

## 1. 기능 요구사항

| ID | 요구사항 | 단계 | 통과 기준(시험) | 상태(10/5) |
|---|---|---|---|---|
| F-01 | KISA 피싱사이트 URL(CSV·오픈 API) 적재: 정규화·중복 제거·거부 사유 기록 | ⓪ | `test_kisa_*` | 구현 |
| F-02 | 신고 URL 단건·CSV 접수 → Case·Seed Candidate 생성 | ⓪ | `test_api::test_full_flow_review_rbac` | 구현 |
| F-03 | 네이버 검색 API(웹문서) Seed — 공개 주의보 키워드 한정, 일 25,000회 이내 | ⓪ | 1주차 | 설계 확정 |
| F-04 | 접근 전 검사: URL 정규화 → DNS → 사설·예약 IP 차단 | ⓪① | `test_url_policy` | 구현 |
| F-05 | 우선순위 큐·visited 집합·예산(깊이·후보 수·도메인·시간) | ⓪ | `test_discovery` | 구현(인메모리) |
| F-06 | 관찰 링크·리다이렉트·폼 action·스크립트 재큐잉, 허용목록은 IMPERSONATES 로만 기록 | ⓪ | `test_discovery`, `test_pipeline_e2e` | 구현 |
| F-07 | 격리 Chromium 렌더링: 화면·DOM·폼·요청 메타데이터·리다이렉트 경로 | ① | `test_browser_agent` | 구현 |
| F-08 | 렌더링 녹화(WebM)·실시간 조사 화면(CDP screencast) | ① | `test_delayed_rendering_captured_with_evidence` | 구현 |
| F-09 | 다운로드·Service Worker·팝업·대화상자 차단, 폼 입력 없음 | ① | `test_popup_and_download_blocked` | 구현 |
| F-10 | 증거 SHA-256·해시 체인·분리 서명 서비스 HMAC, 조회 시 재검증 | ① | `test_evidence_chain` | 구현 |
| F-11 | AI 분석: 유형 후보·confidence·evidence_links·REVIEW_REQUIRED/UNKNOWN·model_meta | ② | `test_ai_engine` | 구현(1차) |
| F-12 | Google Safe Browsing 조회(미등재≠정상, 실패는 ERROR 로 기록 후 진행) | ③ | `test_safebrowsing_*` | 구현 |
| F-13 | 검토 패키지(JSON 미리보기) | ③ | `test_full_flow_review_rbac` | 미리보기 구현, PDF·기관 양식은 3주차 |
| F-14 | 담당자 판정: reviewer 역할만, 사유 필수, 감사로그 | ③ | `test_full_flow_review_rbac` | 구현 |
| F-15 | 실시간 파이프라인 UI(SSE): 단계별 대기·진행·완료·실패, 발견·대기·조사·검토 건수, 관계 그래프 | UI | 수동 시연 + `test_event_bus_replay_and_stats` | 구현 |

## 2. 보안 요구사항(요약 — 상세는 04_threat_model.md)

- S-01 SSRF 이중 방어: 앱 검사(1차) + Worker 전용망·egress 프록시(2차, 연결 시점 IP 재확인·IP 고정).
- S-02 수집 데이터는 전부 불신: React 기본 이스케이프, CSP, 수집 HTML 은 `text/plain` 첨부로만 제공.
- S-03 AI 는 판정 권한 없음: 스키마로 `decision_authority="NONE"` 고정, 자동화 계정 판정 차단(API·DB 트리거).
- S-04 증거 변조 탐지 100%(R2): 파일 단독, 파일+해시, 레코드 해시 재계산, 중간·끝 레코드 삭제.
- S-05 Worker 는 DB·큐·서명 자격증명 없음. 수집 API(ingest-gw) 경로만 접근.
- S-06 비밀값은 `.env`/`secrets/`(gitignore), 토큰은 해시로만 저장, 로그에 키·토큰 미기록.
- S-07 공급망: lockfile·이미지 버전 고정, SAST(Semgrep·Bandit)·SCA(pip-audit·npm audit)·gitleaks CI.

## 3. 범위(In / Out)

**In**: 공개 소스(KISA 공공데이터·신고 URL·공식 검색 API)에서 시작해 관찰된 연결 관계만 제한적으로 확장, 공개 페이지 1회 렌더링, 증거 보존, AI 분석 의견, 담당자 검토 패키지.

**Out(하지 않음)**: 인터넷 전체 무차별 크롤링, DNS 대입 탐색, 로그인·CAPTCHA·인증 우회, 결제·개인정보 입력, 취약점 공격, 외부 서비스 자동 신고·제출, VirusTotal·다중 피드·대규모 분산 Worker(후속 단계).

## 4. 비기능 요구사항

| 항목 | 기준 |
|---|---|
| 조사 1건 시간 상한 | 페이지 20초, 후보 60초(Worker 강제 종료), 사건 600초 |
| 자원 상한 | 요청 300건/페이지, 리다이렉트 10단계, HTML 2MB, Worker 메모리 2GB·PID 512 |
| 탐색 예산(기본) | 깊이 2, 사건당 후보 30, 도메인당 5 (`SAFETRACE_MAX_*`) |
| 재현성 | 규칙 표 해시·모델 버전을 `model_meta` 에 기록, 평가셋 버전 고정(d1s-1.0, d3-1.0, d4-1.0) |
| 가용성 | Safe Browsing·검색 API 장애 시 ERROR 기록 후 핵심 흐름 계속 |

## 5. 일정 연결(기획서 2.9)

| 기간 | 이 문서의 요구사항 |
|---|---|
| 사전준비(~10/5) | F-01,02,04~12,14,15 구현, F-03·13 설계 확정 |
| 1주차 | 인메모리 → PostgreSQL·Redis Streams 교체, F-03, 계정 DB·Argon2id |
| 2주차 | RDAP 신규 등록 가점, 관계 그래프 영속화, D1-R 동결 |
| 3주차 | F-13 PDF·기관 양식, D4 평가, 통합 보안 시험 |
