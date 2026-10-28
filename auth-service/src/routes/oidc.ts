import { Router, Request, Response } from 'express';
import { pool, config } from '../config';
import { verifyAccessToken } from '../keys';

const router = Router();

// /.well-known/openid-configuration — discovery
router.get('/.well-known/openid-configuration', (_req, res) => {
  res.json({
    issuer: config.issuer,
    authorization_endpoint: `${config.issuer}/authorize`,
    token_endpoint: `${config.issuer}/token`,
    userinfo_endpoint: `${config.issuer}/userinfo`,
    jwks_uri: `${config.issuer}/.well-known/jwks.json`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
    code_challenge_methods_supported: ['S256'], // plain intentionally unsupported
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'profile', 'email', 'roles'],
  });
});

// /.well-known/jwks.json — public keys
router.get('/.well-known/jwks.json', async (_req, res) => {
  const { publicJwks } = await import('../keys');
  res.json(await publicJwks());
});

// /userinfo — Bearer access token
router.get('/userinfo', async (req: Request, res: Response) => {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'invalid_token' });
  try {
    const claims = await verifyAccessToken(auth.slice(7)) as any;
    if (!claims.scope?.includes('openid')) return res.status(403).json({ error: 'insufficient_scope' });
    const { rows } = await pool.query(
      `SELECT id, username, email, status FROM users WHERE id = $1`, [claims.sub]
    );
    if (!rows.length || rows[0].status !== 'active') return res.status(401).json({ error: 'invalid_token' });
    const u = rows[0];
    const out: Record<string, unknown> = { sub: u.id, username: u.username };
    if (String(claims.scope).includes('email')) out.email = u.email;
    if (String(claims.scope).includes('roles')) out.roles = claims.roles;
    res.json(out);
  } catch {
    res.status(401).json({ error: 'invalid_token' });
  }
});

export default router;
