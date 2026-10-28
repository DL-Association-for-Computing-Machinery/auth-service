-- 004: refresh_tokens 绑定 nonce，刷新签发的 id_token 携带与初次认证相同的 nonce（OIDC Core 12.2）
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS nonce text;
