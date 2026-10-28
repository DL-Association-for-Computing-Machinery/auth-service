import { Router, Request, Response } from 'express';
import { pool, config } from '../config';
import { sha256, verifyAccessToken, loadSigningKey } from '../keys';
import { audit } from '../audit';

const router = Router();

async function authenticateClient(req: Request): Promise<{ clientId: string } | null> {
  let clientId: string | undefined, clientSecret: string | undefined;
  const auth = req.headers.authorization;
  if (auth?.startsWith('Basic ')) {
    [clientId, clientSecret] = Buffer.from(auth.slice(6), 'base64').toString().split(':');
  } else if (req.body.client_id) {
    clientId = req.body.client_id;
    clientSecret = req.body.client_secret;
  }
  if (!clientId || !clientSecret) return null;
  const { rows } = await pool.query(`SELECT client_id FROM clients WHERE client_id = $1 AND is_confidential = true`, [clientId]);
  if (!rows.length) return null;
  const argon2 = await import('argon2');
  // secret hash stored; verify via clients table requires hash — refetch full row
  const { rows: full } = await pool.query(`SELECT client_secret_hash FROM clients WHERE client_id = $1`, [clientId]);
  if (!(await argon2.verify(full[0].client_secret_hash, clientSecret))) return null;
  return { clientId };
}

/** POST /revoke (RFC 7009) — invalidate access or refresh token. Always 200. */
router.post('/revoke', async (req: Request, res: Response) => {
  const client = await authenticateClient(req);
  if (!client) return res.status(401).json({ error: 'invalid_client' });
  const { token } = req.body;
  if (!token) return res.json({}); // per RFC 7009: unsupported tokens are ignored, 200 anyway

  const { rows: rt } = await pool.query(
    `UPDATE refresh_tokens SET revoked = true
     WHERE token_hash = $1 AND client_id = $2 RETURNING user_id, family_id`,
    [sha256(token), client.clientId]
  );
  if (rt.length) {
    await audit(rt[0].user_id, client.clientId, 'revoke_refresh', req, { family_id: rt[0].family_id });
    return res.json({});
  }
  // access token: black-list jti until its expiry (immediate revocation for JWT)
  try {
    const claims = (await verifyAccessToken(token)) as any;
    if (claims.jti) {
      await pool.query(
        `INSERT INTO revoked_jtis (jti, expires_at) VALUES ($1, to_timestamp($2))
         ON CONFLICT (jti) DO NOTHING`,
        [claims.jti, claims.exp]
      );
      await audit(claims.sub, client.clientId, 'revoke_access', req, {});
    }
  } catch { /* invalid/expired token: RFC says respond 200 */ }
  res.json({});
});

/** POST /introspect (RFC 7662) — token status for resource servers. Requires client auth. */
router.post('/introspect', async (req: Request, res: Response) => {
  const client = await authenticateClient(req);
  if (!client) return res.status(401).json({ error: 'invalid_client' });
  const { token } = req.body;
  if (!token) return res.json({ active: false });

  // refresh tokens first
  const { rows: rt } = await pool.query(
    `SELECT 1 FROM refresh_tokens WHERE token_hash = $1 AND client_id = $2
       AND revoked = false AND rotated = false AND expires_at > now()`,
    [sha256(token), client.clientId]
  );
  if (rt.length) return res.json({ active: true, token_type: 'refresh_token' });

  // access tokens
  try {
    const claims = (await verifyAccessToken(token)) as any;
    const { rows: revoked } = await pool.query(`SELECT 1 FROM revoked_jtis WHERE jti = $1`, [claims.jti]);
    // client_credentials token（sub=client:{id}）无对应用户行，跳过用户状态检查
    const isClientToken = typeof claims.sub === 'string' && claims.sub.startsWith('client:');
    const { rows: userOk } = isClientToken
      ? { rows: [1] }
      : await pool.query(`SELECT 1 FROM users WHERE id = $1 AND status = 'active'`, [claims.sub]);
    return res.json({
      active: !revoked.length && !!userOk.length,
      sub: claims.sub,
      aud: claims.aud,
      scope: claims.scope,
      roles: claims.roles,
      exp: claims.exp,
      iss: claims.iss,
    });
  } catch {
    return res.json({ active: false });
  }
});

/** GET/POST /logout (RP-initiated logout): revoke all token families of that user+client, then redirect. */
function logout(req: Request, res: Response) {
  const hint = (req.method === 'GET' ? req.query.id_token_hint : req.body?.id_token_hint) as string | undefined;
  const postLogout = (req.method === 'GET' ? req.query.post_logout_redirect_uri : req.body?.post_logout_redirect_uri) as string | undefined;
  const run = async () => {
    let claims: any = null;
    if (hint) {
      // 必须验签：伪造的 hint 不得触发任意用户 token 吊销（OIDC RP-initiated logout 要求校验 iss/签名）
      try {
        const { jwtVerify } = await import('jose');
        claims = (await jwtVerify(hint, (await loadSigningKey()).publicKey, { issuer: config.issuer, algorithms: ['RS256'] })).payload;
      } catch {
        claims = null; // 无效/过期/伪造 hint：不据此吊销，走普通登出页
      }
    }
    if (claims?.sub && claims?.aud) {
      const clientId = claims.aud as string;
      await pool.query(
        `UPDATE refresh_tokens SET revoked = true WHERE user_id = $1 AND client_id = $2 AND revoked = false`,
        [claims.sub, clientId]
      );
      await audit(claims.sub as string, clientId, 'logout', req, {});
      if (postLogout) {
        const { rows } = await pool.query(`SELECT post_logout_uris FROM clients WHERE client_id = $1`, [clientId]);
        if (rows[0]?.post_logout_uris?.includes(postLogout)) return res.redirect(302, postLogout);
      }
    }
    res.type('html').send('<!doctype html><meta charset="utf-8"><p>已登出。您可以关闭此页面。</p>');
  };
  run().catch(() => res.status(500).json({ error: 'server_error' }));
}
router.get('/logout', logout);
router.post('/logout', logout);

export default router;
