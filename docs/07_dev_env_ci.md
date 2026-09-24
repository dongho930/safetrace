# 07. 개발환경·저장소·CI (설계 확정본 v1.0)

## 1. 저장소 구조

```
backend/            Python 패키지 safetrace (src 레이아웃), tests/, requirements.lock
  src/safetrace/
    agent/          ① Browser Agent (browser.py, extract.py)
    ai/             ② AI Decision Engine (features, rules, zeroshot, engine)
    discovery/      ⓪ 후보 발굴 정책 (policy, allowlist, similarity)
    evidence/       증거 원장·서명 클라이언트
    signer/         분리 서명 서비스
    proxy/          egress 프록시
    pipeline/       오케스트레이터·이벤트 버스·패키지
    api/            FastAPI 앱·RBAC
    ingest/         KISA 적재
    reputation/     Safe Browsing
    worker/         조사 Worker
frontend/           React 19 + TypeScript + Vite 콘솔
infra/              docker-compose, Dockerfile, nginx(ingest-gw·console), db/schema.sql, 격리 검증 스크립트
data/               d1s(합성)·d3(정상 사이트)·d4(자율 발굴 시험군)·d1r(실데이터 스냅샷, 커밋 제외)
tools/              eval(평가 실행기)·collect(D1-R 수집기)
docs/               설계 확정 문서
scripts/            gen_secrets.py, dev_local.py
```

## 2. 로컬 개발(도커 없이)

```powershell
py -3.14 -m venv .venv                      # 3.13 이상
.venv\Scripts\python -m pip install -c backend\requirements.lock -e "backend[browser,dev]"
.venv\Scripts\python -m playwright install chromium
.venv\Scripts\python scripts\gen_secrets.py   # .env, secrets/signer_key.hex 생성 + 로그인 토큰 출력
.venv\Scripts\python scripts\dev_local.py     # signer + api(in-process worker) + D1-S 시험 사이트
cd frontend; npm ci; npm run dev             # http://127.0.0.1:5173
```

로컬 모드는 egress 프록시 없이 1차 검사만 적용되므로 **로컬 시험 사이트(D1-S)와 공개 정상 사이트만** 조사한다. 실제 위협 URL 은 반드시 compose 격리 환경에서만.

## 3. 격리 환경(docker compose)

```powershell
python scripts\gen_secrets.py
docker compose --env-file .env -f infra\docker-compose.yml up -d --build
docker compose --env-file .env -f infra\docker-compose.yml exec -T worker python - < infra\scripts\verify_isolation.py
# 콘솔: http://127.0.0.1:8088  (SAFETRACE_CONSOLE_PORT 로 변경)
```

## 4. 품질·보안 게이트(CI: `.github/workflows/ci.yml`)

| 단계 | 도구 | 실패 조건 |
|---|---|---|
| 린트 | ruff | 규칙 위반(E,F,W,I,B,UP,S,ASYNC) |
| 단위·보안 시험 | pytest (`-m "not browser"`) | 실패 1건 이상 |
| 브라우저 통합 시험 | pytest `-m browser` (Chromium) | 실패 1건 이상 |
| SAST | Bandit, Semgrep(`p/python`, `p/owasp-top-ten`, `p/react`, `.semgrep/safetrace.yml`) | High 이상 |
| SCA | pip-audit(lock 기준), npm audit(`--audit-level=high`) | High 이상 |
| 비밀정보 | gitleaks | 검출 1건 이상 |
| 프론트 | `tsc -b`, `vite build` | 타입 오류 |

## 5. 버전 고정

- Python 의존성: `backend/requirements.lock`(전이 포함 정확 버전), 설치 시 `-c` 로 강제
- npm: `frontend/package-lock.json`, `npm ci --ignore-scripts`
- 이미지: `python:3.13.7-slim-bookworm`(api·signer·proxy·worker 공용 베이스, worker 는 lock 의 playwright 로 Chromium 설치), `nginx:1.29-alpine`, `postgres:18-alpine`, `redis:8-alpine` — 1주차에 다이제스트(@sha256) 고정

## 6. 브랜치·리뷰 규칙

- `main` 보호, 기능 브랜치 → PR → CI 통과 + 교차 리뷰 1인(팀원 1 ↔ 2)
- 보안 관련 변경(정책·프록시·원장·RBAC)은 04 위협 모델의 해당 D2 시험을 PR 설명에 명시
- 비밀값·실데이터(`data/d1r/snapshots`)·평가 산출물(`reports/`)은 커밋 금지(.gitignore)
