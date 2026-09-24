-- SafeTrace 데이터 스키마(설계 확정본, docs/03_data_schema.md). PostgreSQL 18.
-- 원칙: 상태의 원본은 DB, 증거·감사로그는 추가 전용(UPDATE/DELETE 불가), 앱 계정은 최소 권한.

CREATE TYPE seed_source AS ENUM ('KISA', 'REPORT', 'SEARCH_API', 'DISCOVERED');
CREATE TYPE relation AS ENUM ('SEED', 'LINK', 'REDIRECT', 'RESOURCE', 'SCRIPT', 'FORM_ACTION', 'IMPERSONATES');
CREATE TYPE candidate_status AS ENUM (
  'DISCOVERED', 'QUEUED', 'SCREENING', 'INVESTIGATING', 'ANALYZING', 'PACKAGING',
  'REVIEW_REQUIRED', 'DECIDED', 'SKIPPED', 'BLOCKED', 'UNREACHABLE', 'FAILED');
CREATE TYPE evidence_type AS ENUM ('SCREENSHOT', 'HTML', 'OBSERVATION', 'VIDEO', 'HAR');
CREATE TYPE threat_type AS ENUM ('PHISHING', 'SCAM', 'ILLEGAL_GAMBLING_SUSPECTED', 'MALWARE', 'OTHER');
CREATE TYPE review_state AS ENUM ('REVIEW_REQUIRED', 'UNKNOWN');
CREATE TYPE decision AS ENUM ('THREAT_CONFIRMED', 'NOT_THREAT', 'INCONCLUSIVE');
CREATE TYPE reputation_result AS ENUM ('LISTED', 'NOT_LISTED', 'ERROR', 'SKIPPED');
CREATE TYPE user_role AS ENUM ('viewer', 'investigator', 'reviewer', 'automation');

CREATE TABLE app_user (
  user_id        text PRIMARY KEY CHECK (user_id ~ '^[a-z0-9_.-]{2,64}$'),
  role           user_role NOT NULL,
  password_hash  text,                       -- Argon2id (자동화 계정은 NULL, API 토큰만)
  token_sha256   char(64) UNIQUE,
  is_automation  boolean GENERATED ALWAYS AS (role = 'automation') STORED,
  created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE "case" (
  case_id       text PRIMARY KEY,
  source        seed_source NOT NULL,
  original_url  varchar(2048) NOT NULL,
  submitted_by  text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE candidate (
  candidate_id        text PRIMARY KEY,
  case_id             text NOT NULL REFERENCES "case"(case_id),
  source              seed_source NOT NULL,
  original_url        varchar(2048) NOT NULL,
  normalized_url      varchar(2048) NOT NULL,
  registrable_domain  varchar(256) NOT NULL,
  discovered_from     text REFERENCES candidate(candidate_id),
  relation            relation NOT NULL DEFAULT 'SEED',
  depth               smallint NOT NULL DEFAULT 0 CHECK (depth BETWEEN 0 AND 5),
  priority            real NOT NULL DEFAULT 0,
  score_reasons       jsonb NOT NULL DEFAULT '[]',
  status              candidate_status NOT NULL DEFAULT 'DISCOVERED',
  status_reason       varchar(256) NOT NULL DEFAULT '',
  idempotency_key     char(64) NOT NULL,
  version             integer NOT NULL DEFAULT 1,   -- 낙관적 잠금
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  UNIQUE (case_id, idempotency_key)                 -- 사건 내 visited 집합(중복·순환 차단)
);
CREATE INDEX candidate_queue_idx ON candidate (status, priority DESC) WHERE status = 'QUEUED';
CREATE INDEX candidate_domain_idx ON candidate (case_id, registrable_domain);

CREATE TABLE candidate_edge (   -- 관계 그래프(허용목록 사칭 대상 포함)
  from_candidate  text NOT NULL REFERENCES candidate(candidate_id),
  to_candidate    text REFERENCES candidate(candidate_id),
  to_domain       varchar(256),
  relation        relation NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  CHECK ((to_candidate IS NULL) <> (to_domain IS NULL))
);

CREATE TABLE observation (
  candidate_id     text PRIMARY KEY REFERENCES candidate(candidate_id),
  final_url        varchar(2048),
  reachable        boolean NOT NULL,
  redirect_chain   jsonb NOT NULL,
  dom_summary      jsonb NOT NULL,
  forms            jsonb NOT NULL,
  request_summary  jsonb NOT NULL,
  policy_blocks    text[] NOT NULL DEFAULT '{}',
  errors           text[] NOT NULL DEFAULT '{}',
  agent_version    varchar(64) NOT NULL,
  started_at       timestamptz NOT NULL,
  finished_at      timestamptz
);

-- 증거 원장: 해시 체인 + 분리 키 HMAC. seq 는 전역 단조 증가.
CREATE TABLE evidence (
  seq           bigint PRIMARY KEY,
  evidence_id   text NOT NULL UNIQUE,
  case_id       text NOT NULL REFERENCES "case"(case_id),
  candidate_id  text NOT NULL REFERENCES candidate(candidate_id),
  type          evidence_type NOT NULL,
  object_path   varchar(2048) NOT NULL,
  sha256        char(64) NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  size          bigint NOT NULL CHECK (size >= 0),
  captured_at   timestamptz NOT NULL,
  version       integer NOT NULL DEFAULT 1,
  prev_hash     char(64) NOT NULL,
  record_hash   char(64) NOT NULL UNIQUE,
  hmac_sig      char(64) NOT NULL,
  key_id        varchar(64) NOT NULL
);

CREATE TABLE ai_analysis (
  analysis_id    text PRIMARY KEY,
  candidate_id   text NOT NULL REFERENCES candidate(candidate_id),
  model_version  varchar(256) NOT NULL,
  model_hash     varchar(64) NOT NULL,
  backend        varchar(64) NOT NULL,
  threat_types   jsonb NOT NULL,          -- [{type, confidence, evidence_links[]}]
  state          review_state NOT NULL,
  state_reason   varchar(300) NOT NULL,
  inferred_at    timestamptz NOT NULL
);

CREATE TABLE reputation (
  candidate_id  text NOT NULL REFERENCES candidate(candidate_id),
  provider      varchar(64) NOT NULL,
  url           varchar(2048) NOT NULL,
  result        reputation_result NOT NULL,
  threats       text[] NOT NULL DEFAULT '{}',
  detail        varchar(256) NOT NULL DEFAULT '',
  checked_at    timestamptz NOT NULL
);

CREATE TABLE review (
  candidate_id  text PRIMARY KEY REFERENCES candidate(candidate_id),
  reviewer_id   text NOT NULL REFERENCES app_user(user_id),
  decision      decision NOT NULL,
  reason        varchar(2000) NOT NULL CHECK (length(reason) >= 5),
  decided_at    timestamptz NOT NULL DEFAULT now()
);

-- R7: 자동화 계정은 판정을 확정할 수 없다(앱 검사와 별개로 DB 에서도 강제).
CREATE FUNCTION review_forbid_automation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (SELECT role FROM app_user WHERE user_id = NEW.reviewer_id) <> 'reviewer' THEN
    RAISE EXCEPTION 'only reviewer role may decide';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER review_role_check BEFORE INSERT OR UPDATE ON review
  FOR EACH ROW EXECUTE FUNCTION review_forbid_automation();

CREATE TABLE audit_log (
  id         bigserial PRIMARY KEY,
  actor      varchar(256) NOT NULL,
  action     varchar(256) NOT NULL,
  target     varchar(256) NOT NULL,
  result     varchar(8) NOT NULL CHECK (result IN ('OK', 'DENIED', 'ERROR')),
  detail     varchar(256) NOT NULL DEFAULT '',
  ts         timestamptz NOT NULL DEFAULT now()
);

-- 트랜잭셔널 아웃박스: 상태 변경과 같은 트랜잭션에 기록 → 릴레이가 Redis Streams 로 발행.
CREATE TABLE outbox (
  id          bigserial PRIMARY KEY,
  stream      varchar(64) NOT NULL,
  payload     jsonb NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz
);
CREATE INDEX outbox_pending_idx ON outbox (id) WHERE published_at IS NULL;

-- 추가 전용 강제
CREATE FUNCTION forbid_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END $$;
CREATE TRIGGER evidence_append_only BEFORE UPDATE OR DELETE ON evidence
  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

-- 최소 권한 앱 계정(비밀번호는 배포 시 ALTER ROLE 로 설정)
CREATE ROLE safetrace_app NOLOGIN;
GRANT SELECT, INSERT, UPDATE ON "case", candidate, candidate_edge, observation, ai_analysis, reputation, review, outbox
  TO safetrace_app;
GRANT SELECT, INSERT ON evidence, audit_log TO safetrace_app;
GRANT SELECT ON app_user TO safetrace_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO safetrace_app;
REVOKE TRUNCATE ON evidence, audit_log FROM PUBLIC;
