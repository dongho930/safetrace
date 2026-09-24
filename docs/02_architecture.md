# 02. 아키텍처 (설계 확정본 v1.0)

## 1. 구성요소

```
                 ┌──────────── 사용자 영역(front) ────────────┐
 담당자 브라우저 ─▶ console(nginx, CSP) ──/api──▶ api(FastAPI)  │
                 └────────────────────────────────────────────┘
                                               │ svc(internal)
        ┌──────────────────────────────────────┼──────────────────────────┐
        │  signer(HMAC 키 보유)   postgres   redis   ingest-gw(nginx)     │
        └──────────────────────────────────────┼──────────────────────────┘
                                               │ inv(internal)
        ┌──────────────── 격리 조사 영역 ───────┼──────────────────────────┐
        │  worker(Playwright, 비관리자) ──▶ ingest-gw(/ingest/v1/* 만)     │
        │           └──── 모든 외부 트래픽 ──▶ egress-proxy ──▶ (out) 인터넷 │
        └─────────────────────────────────────────────────────────────────┘
```

| 구성요소 | 코드 | 역할 | 신뢰 경계 |
|---|---|---|---|
| api | `backend/src/safetrace/api/app.py` | 콘솔 API·SSE·수집 API, 오케스트레이터 호스팅 | 내부 서비스 |
| orchestrator | `pipeline/orchestrator.py` | 상태 전이·감사로그·이벤트 발행의 단일 지점 | 내부 서비스 |
| discovery | `discovery/policy.py` | 재큐잉 점수·예산·visited | 내부 서비스 |
| worker | `worker/main.py`, `agent/browser.py` | 격리 렌더링·증거 수집 | 격리 조사 |
| egress-proxy | `proxy/egress.py` | 유일한 외부 출구, 연결 시점 IP 재검사·IP 고정 | 격리 조사 ↔ 외부 |
| ingest-gw | `infra/ingest-gw/nginx.conf` | Worker 에 `/ingest/v1/*` POST 만 노출 | 격리 조사 ↔ 내부 |
| signer | `signer/app.py` | HMAC 키 단독 보유, 추가 전용 서명·high-water mark | 내부(키 격리) |
| ledger | `evidence/ledger.py` | 증거 객체·해시 체인 원장 | 내부 서비스 |
| engine | `ai/engine.py` | 규칙 특징 + (선택) 로컬 제로샷 → 구조화 출력 | 내부 서비스 |
| console | `frontend/` | 실시간 파이프라인·후보 그래프·증거·판정 | 사용자 |

## 2. 처리 흐름(⓪→①→②→③)

1. **Seed 접수** `POST /api/cases`, `POST /api/seeds/kisa` → `Frontier.seed()` (정규화·idempotency_key) → `DISCOVERED`
2. **접근 전 검사** `_screen()`: `UrlPolicy.check_url()` — 사설·예약 IP면 `BLOCKED`, DNS 실패면 `UNREACHABLE`, 통과 시 `QUEUED`(우선순위 큐)
3. **조사** Worker `lease` → `INVESTIGATING` → BrowserAgent: 모든 요청 가로채기(1차 검사), 문서 3xx 는 Location 검사 후 meta refresh 로 중계(hop 마다 재검사), 녹화·screencast·DOM·폼·요청 메타데이터 → `artifact` 업로드 → `result`
4. **증거 저장** `EvidenceLedger.append()` — SHA-256, prev_hash, record_hash, signer HMAC
5. **AI 분석** `DecisionEngine.analyze()` → `ANALYZING` → AIAnalysis(REVIEW_REQUIRED/UNKNOWN)
6. **평판·패키지** Safe Browsing → `PACKAGING`
7. **재큐잉** `Frontier.expand()` — 허용목록 IMPERSONATES 기록, 점수 상위만 예산 안에서 `DISCOVERED` → 2단계로
8. **담당자 검토** `REVIEW_REQUIRED` → reviewer 판정 → `DECIDED`

상태 전이마다 `candidate.status` 이벤트(SSE)와 감사로그가 한 곳(`_set_status`)에서 기록된다.

## 3. 네트워크 격리(docker-compose)

| 네트워크 | internal | 연결 | 목적 |
|---|---|---|---|
| inv | ✅ | worker, egress-proxy, ingest-gw | 인터넷 출구 없음. Worker 의 유일한 망 |
| svc | ✅ | api, signer, postgres, redis, ingest-gw | 내부 서비스. Worker 미연결 |
| out | ❌ | egress-proxy, api | 외부 출구(api 는 Safe Browsing·사전 DNS 검사) |
| front | ❌ | console, api | 사용자 영역, 127.0.0.1 에만 게시 |

- Worker 는 `inv` 에만 연결되어 api·signer·postgres·redis 이름 해석·접속이 불가능하다(`infra/scripts/verify_isolation.py`).
- Worker 망에는 외부 DNS 가 없으므로 Worker 의 1차 검사는 정규화·IP 리터럴까지, 도메인의 IP 검사는 프록시가 연결 시점에 한다.
- 모든 컨테이너: `read_only`, `cap_drop: ALL`, `no-new-privileges`, 메모리·PID 상한.

## 4. SSRF 이중 방어 상세

| 계층 | 위치 | 검사 |
|---|---|---|
| 1차 | api `_screen`, BrowserAgent `_route` | 스킴(http/https), userinfo 금지, 위험 포트, 10진·8진·16진 IP 표기, IDN→punycode, DNS 응답 전부 공개 대역 |
| 1차(hop) | BrowserAgent `_route_document` | 문서 3xx 를 브라우저에 넘기지 않고 Location 재검사 후 meta refresh 로 새 탐색 → 다음 hop 도 재검사 |
| 2차 | egress-proxy | 연결 시점 DNS 해석 → 전부 공개 대역일 때 **검증한 IP 로만** 연결(DNS Rebinding 방지), 요청마다 연결 종료 |
| 2차 | Docker internal 망 | 프록시를 우회한 직접 연결 경로 자체가 없음 |

하위 리소스(이미지·스크립트)의 후속 리다이렉트 hop 은 Chromium 내부에서 처리되므로 2차(프록시)가 차단한다.

## 5. 1주차 교체 계획(인터페이스 불변)

| 사전준비 | 1주차 | 교체 지점 |
|---|---|---|
| `Orchestrator` 인메모리 dict | PostgreSQL(`infra/db/schema.sql`) | 저장소 계층 추가, `_set_status` 에서 트랜잭션 + outbox |
| `asyncio.PriorityQueue` | Redis Streams `st:jobs`(consumer group, XAUTOCLAIM 으로 lease 만료 회수) | `lease()`/`_screen()` |
| `EventBus` 인메모리 | Redis Streams `st:events`(Last-Event-ID = stream id) | `publish`/`subscribe` |
| SQLite 원장 | PostgreSQL `evidence`(추가 전용 트리거) | `EvidenceLedger` 저장 함수 |
| 토큰 RBAC | 계정 DB + Argon2id 로그인, 세션 토큰 | `api/auth.py` |
