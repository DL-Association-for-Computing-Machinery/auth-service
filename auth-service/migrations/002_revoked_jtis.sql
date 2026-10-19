-- M2: immediate revocation support for JWT access tokens
CREATE TABLE IF NOT EXISTS revoked_jtis (
  jti text PRIMARY KEY,
  expires_at timestamptz NOT NULL   -- cleanup: DELETE WHERE expires_at < now() periodically
);
CREATE INDEX IF NOT EXISTS idx_revoked_jtis_exp ON revoked_jtis(expires_at);
