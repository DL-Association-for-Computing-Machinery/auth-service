-- auth domain schema v0.1
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  username text UNIQUE NOT NULL,
  password_hash text NOT NULL,           -- argon2id
  email text UNIQUE,
  status text NOT NULL DEFAULT 'active', -- active | locked | disabled
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS roles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code text UNIQUE NOT NULL,
  name text NOT NULL
);

CREATE TABLE IF NOT EXISTS user_roles (
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS clients (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id text UNIQUE NOT NULL,
  client_secret_hash text NOT NULL,      -- argon2id of secret
  name text NOT NULL,
  redirect_uris text[] NOT NULL,         -- exact match only
  post_logout_uris text[] NOT NULL DEFAULT '{}',
  scopes text[] NOT NULL DEFAULT '{}',
  token_lifetime_s int NOT NULL DEFAULT 600,
  is_confidential boolean NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS authorization_codes (
  code_hash text PRIMARY KEY,            -- sha256 of code
  client_id text NOT NULL,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  redirect_uri text NOT NULL,
  scope text NOT NULL,
  code_challenge text NOT NULL,          -- PKCE S256 only
  nonce text,
  expires_at timestamptz NOT NULL,
  used boolean NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash text UNIQUE NOT NULL,       -- sha256 of token
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client_id text NOT NULL,
  family_id uuid NOT NULL,               -- replay detection: revoke whole family
  scope text NOT NULL,
  rotated boolean NOT NULL DEFAULT false,
  revoked boolean NOT NULL DEFAULT false,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_refresh_family ON refresh_tokens(family_id);

CREATE TABLE IF NOT EXISTS jwks (
  kid text PRIMARY KEY,
  algorithm text NOT NULL DEFAULT 'RS256',
  public_key_pem text NOT NULL,
  private_key_encrypted text,            -- prod: KMS / env-encrypted
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id bigserial PRIMARY KEY,
  user_id uuid,
  client_id text,
  event text NOT NULL,                   -- login | code_issue | token_issue | refresh | revoke | login_fail
  ip text,
  user_agent text,
  detail jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);
