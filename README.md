# SafeTrace

AI 기반 위협 의심 사이트 **자율 후보 발굴 · 증거화 · 공공 심의 지원** 시스템 — 2026 SW개발보안 경진대회 트랙 C(공공활용).

공공데이터(KISA 피싱사이트 URL)·신고 URL 에서 출발해 관찰된 링크·리다이렉트를 따라 후보를 제한적으로 발굴하고, 격리 브라우저로 동적 증거를 수집·보존한 뒤, 증거 ID 가 연결된 AI 분석 의견과 함께 담당자 검토 패키지를 만든다. **최종 판정은 담당자가 한다.**

```
⓪ Candidate Discovery → ① Browser Agent(격리 Chromium) → ② AI Decision Engine → ③ 검토 패키지 → 담당자 판정
      ▲                         │
      └──── 관찰된 링크·리다이렉트 재큐잉(허용목록 제외·점수·예산) ─┘
```

## 빠른 시작

### A. 격리 환경(권장, Docker)

```powershell
python scripts\gen_secrets.py                    # .env · secrets/ 생성, 콘솔 로그인 토큰 출력(1회)
docker compose --env-file .env -f infra\docker-compose.yml up -d --build
docker compose --env-file .env -f infra\docker-compose.yml exec -T worker python - < infra\scripts\verify_isolation.py
# 콘솔: http://127.0.0.1:8088  (포트: SAFETRACE_CONSOLE_PORT)
```

### B. 로컬 개발(도커 없이, 시험 사이트 전용)

```powershell
py -3.14 -m venv .venv
.venv\Scripts\python -m pip install -c backend\requirements.lock -e "backend[browser,dev]"
.venv\Scripts\python -m playwright install chromium
.venv\Scripts\python scripts\gen_secrets.py
.venv\Scripts\python scripts\dev_local.py        # signer + api(+worker) + D1-S 시험 사이트(localhost:8765)
cd frontend; npm ci; npm run dev                 # http://127.0.0.1:5173
```

로컬 모드에는 egress 프록시가 없으므로 **실제 위협 URL 을 넣지 않는다.** D1-S 예: `http://localhost:8765/p/phish-01.html`, `http://localhost:8765/go/gamble-02/1`.

## 시험·평가

```powershell
cd backend
..\.venv\Scripts\python -m pytest -m "not browser"   # 단위·보안(SSRF·증거 변조·RBAC·AI 스키마)
..\.venv\Scripts\python -m pytest -m browser         # 실제 Chromium 통합(지연 렌더링·리다이렉트 차단·HAR 재생)
cd ..
.venv\Scripts\python tools\eval\run_d1s.py           # R1·R3·R4 (합성 90페이지)
.venv\Scripts\python tools\eval\run_d3.py            # R7 (공개 정상 사이트 184개, 요청 간격 5초)
```

## 문서

| 문서 | 내용 |
|---|---|
| [docs/00_preparation_status.md](docs/00_preparation_status.md) | **사전준비 점검표**(기획서 2.9 항목별 산출물·검증 결과) |
| [docs/01_requirements_scope.md](docs/01_requirements_scope.md) | 요구사항·범위 |
| [docs/02_architecture.md](docs/02_architecture.md) | 아키텍처·네트워크 격리·SSRF 이중 방어 |
| [docs/03_data_schema.md](docs/03_data_schema.md) | 데이터 스키마·상태 머신·증거 해시 규칙·이벤트 |
| [docs/04_threat_model.md](docs/04_threat_model.md) | STRIDE·D2 보안 시험 15종 |
| [docs/05_candidate_discovery_policy.md](docs/05_candidate_discovery_policy.md) | Seed 소스·재큐잉 점수·예산 |
| [docs/06_kisa_data_format.md](docs/06_kisa_data_format.md) | KISA 데이터 적재 형식 |
| [docs/07_dev_env_ci.md](docs/07_dev_env_ci.md) | 개발환경·저장소·CI |
| [docs/08_evaluation_plan.md](docs/08_evaluation_plan.md) | 평가셋(D1-R·D1-S·D2·D3·D4)·지표·사전 측정값 |
| [docs/09_interfaces.md](docs/09_interfaces.md) | API·수집 API·서명 서비스·내부 인터페이스 |

## 운영 원칙

- AI confidence 는 모델의 기술적 신뢰도이며 법적 위법성의 확률이 아니다. AI·자동화 계정은 판정 권한이 없다.
- 외부 평판 DB 미등재는 정상(BENIGN)의 근거가 아니다.
- 공개 소스와 관찰된 연결 관계로만 탐색하며 무차별 크롤링·DNS 대입·인증 우회·폼 입력·취약점 공격을 하지 않는다.
