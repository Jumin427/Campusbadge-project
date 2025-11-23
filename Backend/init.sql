-- 확장 기능: 대소문자 구분 없는 문자열 타입(citext), UUID 생성용 함수(pgcrypto)
CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ================================
-- 1. 유저 정보 테이블 (로그인/권한/지갑 매핑)
-- ================================
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),  -- 내부용 PK

  -- 로그인용 ID (학번이나 아이디)
  username      TEXT   NOT NULL UNIQUE,           -- 예: "202322248" 또는 "admin"

  -- 비밀번호 해시 (평문 아님!)
  password_hash TEXT   NOT NULL,

  -- 권한: 일반 유저 / 관리자
  role          TEXT   NOT NULL DEFAULT 'USER'
    CHECK (role IN ('USER','ADMIN')),

  -- 화면에 보여줄 이름/닉네임
  nickname      TEXT   NOT NULL,                  -- 예: "김주민"

  -- 지갑 주소 (지갑 연결용). 대소문자 구분 없는 고유 값
  wallet_address CITEXT UNIQUE,                   -- 나중에 NOT NULL로 바꿔도 됨

  -- 이메일 (로그인/연락용). 대소문자 구분 없는 고유 값
  email         CITEXT NOT NULL UNIQUE,

  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 관리자 계정만 빠르게 조회할 때 쓰는 인덱스
CREATE INDEX IF NOT EXISTS idx_users_admin_only
  ON users (role)
  WHERE role = 'ADMIN';

-- 지갑 주소 기반 조회용 인덱스
CREATE INDEX IF NOT EXISTS idx_users_wallet
  ON users (wallet_address);

-- ================================
-- 1-1. 지갑 풀 테이블 (사전 생성된 지갑 관리)
-- ================================
CREATE TABLE IF NOT EXISTS wallet_pool (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  -- EVM 지갑 주소 (0x로 시작하는 40자리 hex)
  address CITEXT NOT NULL UNIQUE,

  -- 아직 아무에게도 배정 안 됐으면 FALSE, 배정되면 TRUE
  is_used BOOLEAN NOT NULL DEFAULT FALSE,

  -- 어느 유저에게 배정됐는지 (없으면 NULL)
  assigned_user_id UUID REFERENCES users(id),

  -- (선택) private key를 암호화해서 넣고 싶을 때 사용할 칼럼
  encrypted_private_key TEXT,

  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 지갑 풀에서 "미사용 지갑" 빠르게 찾기 위한 인덱스
CREATE INDEX IF NOT EXISTS idx_wallet_pool_unused
  ON wallet_pool (is_used)
  WHERE is_used = FALSE;

-- 어떤 유저에게 어떤 지갑이 배정됐는지 조회용 인덱스
CREATE INDEX IF NOT EXISTS idx_wallet_pool_user
  ON wallet_pool (assigned_user_id);


-- ================================
-- 2. updated_at 자동 업데이트 트리거
-- ================================
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$
BEGIN
  -- users 테이블 updated_at 자동 갱신 트리거
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_users_updated') THEN
    CREATE TRIGGER trg_users_updated
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
  END IF;
END$$;
