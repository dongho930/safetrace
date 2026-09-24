# 04. 위협 모델 — STRIDE + D2 보안 시험 시나리오 (설계 확정본 v1.0)

전제: SafeTrace 는 **공격자가 통제하는 웹 콘텐츠**를 직접 처리한다. 수집된 모든 값(URL·HTML·문구·헤더·파일명·리다이렉트 대상)은 불신 데이터다.

## 1. 신뢰 경계

| 경계 | 넘어오는 것 | 통제 |
|---|---|---|
| TB1 외부 → 격리 조사 | 페이지·스크립트·리다이렉트·다운로드 | Chromium 격리, 요청 가로채기, 다운로드·SW·팝업 차단, 시간·자원 상한 |
| TB2 격리 조사 → 내부 | 관찰 JSON·증거 파일·프레임 | ingest-gw 경로 제한, Worker 토큰, 스키마 검증(`extra=forbid`), 크기 상한, lease 일치 확인 |
| TB3 내부 → 외부 | Safe Browsing 조회, 검색 API | 키 분리·로그 미기록, 호출 간격·타임아웃, 실패 격리 |
| TB4 내부 → 사용자 | 후보·증거·AI 근거 | RBAC, 이스케이프·CSP, 수집 HTML 비렌더링, 증거 조회 시 재검증 |
| TB5 저장소 ↔ 서명 | record_hash | 키는 signer 에만, 추가 전용 서명(seq 재서명·건너뛰기 거부) |

## 2. STRIDE

| 분류 | 위협 | 발생 지점 | 대응 | 검증 |
|---|---|---|---|---|
| S 스푸핑 | Worker 사칭해 결과 주입 | ingest API | Worker 토큰(상수 시간 비교), job_id·worker_id·candidate_id 일치 | `test_ingest_requires_worker_token` |
| S | 담당자 사칭·권한 상승 | 콘솔 API | 토큰 해시 저장, RBAC, 판정은 reviewer 만 | `test_full_flow_review_rbac` |
| T 변조 | 증거 파일·해시 동시 수정(내부자 포함) | 증거 저장소 | 해시 체인 + 분리 키 HMAC + high-water mark, 조회 시 재검증 | `test_evidence_chain`(9종) |
| T | 수집 페이지가 추출기 조작(프로토타입 오염) | Browser Agent | DOM 직렬화 후 Python 표준 파서로 추출(페이지 JS 가 추출 로직에 접근 불가) | `test_extract_*` |
| R 부인 | 판정·조회 행위 부인 | API | 추가 전용 감사로그(거부 포함), 판정 사유 필수 | `test_full_flow_review_rbac` |
| I 정보 노출 | SSRF 로 내부망·메타데이터 조회 | Agent·프록시 | 1차 정책 + hop 재검사 + 2차 프록시 + internal 망 | D2-01~08 |
| I | 오류 메시지로 내부 정보 노출 | API | 일반화 오류 코드, 운영 모드 docs 비활성화 | 코드 리뷰 |
| I | 비밀값 커밋·로그 노출 | 저장소·로그 | `.env`/`secrets/` gitignore, SecretStr, gitleaks | CI |
| D 서비스 거부 | 무한 리다이렉트·대용량 DOM·요청 폭주 | Agent | 리다이렉트 10·요청 300·HTML 2MB·시간 상한, 컨테이너 메모리·PID 상한 | D2-09, D2-11 |
| D | 탐색 폭주(재큐잉 무한 확장) | Discovery | 깊이·후보·도메인 예산, visited | `test_budgets` |
| E 권한 상승 | 자동화 계정·AI 가 판정 확정 | API·DB | RBAC + `decision_authority=NONE` + DB 트리거 | D2-14 |
| E | 수집 HTML 이 콘솔에서 스크립트 실행(저장형 XSS) | Console | React 이스케이프, `dangerouslySetInnerHTML` 금지, CSP `script-src 'self'`, 인라인 style 불사용 | D2-12 |
| E | 프롬프트 인젝션으로 AI 출력·권한 조작 | AI | 페이지 문구는 분류 입력 데이터로만, 생성·도구 실행 경로 없음, 출력 스키마 강제 | D2-13 |

## 3. D2 공격 시나리오 15종(R5: 모두 차단/격리)

| ID | 시나리오 | 기대 결과 | 자동 시험 |
|---|---|---|---|
| D2-01 | 사설·루프백·메타데이터 IP 직접 접수 | BLOCKED(IP_NOT_PUBLIC) | `test_private_seed_blocked_at_screening`, `test_direct_private_target_never_navigated` |
| D2-02 | 10진·8진·16진·IPv4-mapped·NAT64·6to4 IP 표기 우회 | 차단 | `test_obfuscated_ip_literals_blocked`, `test_private_and_reserved_blocked` |
| D2-03 | 공개 페이지 → 302 → 사설 IP / 169.254.169.254 / 127.0.0.1 | hop 차단, 최종 URL 미도달 | `test_redirect_to_private_ip_blocked` |
| D2-04 | DNS 응답에 공개·사설 혼합 | 전체 차단 | `test_mixed_dns_answers_blocked` |
| D2-05 | DNS Rebinding(검사 후 사설로 재해석) | 프록시가 검증 IP 로만 연결 | `test_dns_rebinding_pins_validated_ip` |
| D2-06 | Worker 에서 api·signer·postgres·redis 직접 접속 | 이름 해석·연결 불가 | `infra/scripts/verify_isolation.py` |
| D2-07 | Worker 에서 프록시 우회 직접 인터넷 접속 | 불가(internal 망) | `verify_isolation.py` |
| D2-08 | 프록시 경유 내부 주소·위험 포트·비HTTP 스킴 | 403 | `test_denied_targets`(9종) |
| D2-09 | 무한 리다이렉트 루프 | REDIRECT_LIMIT | `test_redirect_loop_limited` |
| D2-10 | 팝업·자동 다운로드(.apk) | 팝업 무력화, 다운로드 취소 | `test_popup_and_download_blocked` |
| D2-11 | 대용량 DOM·요청 폭주 | HTML_TRUNCATED·REQUEST_LIMIT, 시간 초과 시 강제 종료 | 단위 상한 + 3주차 통합 시험 |
| D2-12 | 수집 문구·HTML 에 스크립트(저장형 XSS) | 콘솔에서 텍스트로만 표시, HTML 증거는 text/plain 첨부 | `test_evidence_content_reverified_on_read`(헤더) + 3주차 브라우저 시험 |
| D2-13 | 페이지 내 프롬프트 인젝션 문구 | 출력 스키마·유형 불변 | `test_prompt_injection_text_does_not_change_output_contract` |
| D2-14 | 자동화·조사자·열람자 계정의 판정 확정 | 403 + 감사로그 DENIED | `test_full_flow_review_rbac` |
| D2-15 | 증거 파일·해시 동시 변조, 레코드 삭제, 체인 재작성 | 100% 탐지 | `test_evidence_chain` |

## 4. 잔여 위험(수용·후속)

| 위험 | 현재 상태 | 계획 |
|---|---|---|
| Chromium 0-day 로 Worker 탈출 | 비관리자·cap_drop·read_only·internal 망으로 피해 범위 제한 | 이미지 주기 갱신, `SAFETRACE_CHROMIUM_SANDBOX=1`(seccomp 프로파일 적용 시) |
| 체인 전체 재작성 + 서명 서비스 동시 장악 | 키 분리로 저장소 권한만으로는 불가 | RFC 3161 TSA 체인 헤드 타임스탬프(외부 가용성에 따라 선택) |
| 서명 후 DB 기록 실패 → TAIL_TRUNCATED 오탐 | 원장 잠금 안에서 서명·기록 | 1주차 PostgreSQL 트랜잭션 + 서명 서비스 재시도 규약 |
| 로컬 개발 모드(프록시 없음)의 하위 리소스 리다이렉트 | 1차 검사만 | 운영·평가는 항상 compose(프록시) 경로 |
