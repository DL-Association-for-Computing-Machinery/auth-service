import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import { pool, config } from '../config';
import { sha256, signToken } from '../keys';
import { audit } from '../audit';

const router = Router();

const errGrant = (res: Response, error: string, desc: string) =>
  res.status(400).json({ error, error_description: desc });

/** Verify PKCE S256: base64url(sha256(verifier)) == stored challenge */
function verifyPkce(verifier: string, challenge: string): boolean {
  if (!/^[\w-]{43,128}$/.test(verifier)) return false;
  const computed = crypto.createHash('sha256').update(verifier).digest('base64url');
  return crypto.timingSafeEqual(Buffer.from(computed), Buffer.from(challenge));
}

/** Client authentication: HTTP Basic or body (client_secret only over TLS). */
async function authenticateClient(req: Request): Promise<{ clientId: string; client: any } | null> {
  let clientId: string | undefined, clientSecret: string | undefined;
  const auth = req.headers.authorization;
  if (auth?.startsWith('Basic ')) {
    [clientId, clientSecret] = Buffer.from(auth.slice(6), 'base64').toString().split(':');
  } else if (req.body.client_id) {
    clientId = req.body.client_id;
    clientSecret = req.body.client_secret;
  }
  if (!clientId || !clientSecret) return null;
  const { rows } = await pool.query(
    `SELECT * FROM clients WHERE client_id = $1 AND is_confidential = true`, [clientId]
  );
  if (!rows.length) return null;
  const argon2 = (await import('argon2'));
  if (!(await argon2.verify(rows[0].client_secret_hash, clientSecret))) return null;
  return { clientId, client: rows[0] };
}

router.post('/token', async (req: Request, res: Response) => {
  const grant = req.body.grant_type;
  if (grant === 'authorization_code') return authorizationCodeGrant(req, res);
  if (grant === 'refresh_token') return refreshTokenGrant(req, res);
  if (grant === 'client_credentials') return clientCredentialsGrant(req, res);
  return errGrant(res, 'unsupported_grant_type', 'only authorization_code, refresh_token and client_credentials supported');
});

/** client_credentials (RFC 6749 §4.4): 机密客户端 M2M，无 refresh token，无用户上下文。 */
async function clientCredentialsGrant(req: Request, res: Response) {
  const clientAuth = await authenticateClient(req);
  if (!clientAuth) return errGrant(res, 'invalid_client', 'client authentication failed');
  const allowed = clientAuth.client.scopes as string[];
  const requested = String(req.body.scope || 'openid').split(' ').filter(Boolean);
  const scope = requested.filter((s) => allowed.includes(s));
  if (!scope.length) return errGrant(res, 'invalid_scope', 'no requested scope is allowed for client');

  const accessToken = await signToken(
    { sub: `client:${clientAuth.clientId}`, aud: `${clientAuth.clientId}-api`, scope: scope.join(' '), roles: [], jti: crypto.randomUUID() },
    clientAuth.client.token_lifetime_s,
    'access'
  );
  await audit(null, clientAuth.clientId, 'client_credentials_issue', req, { scope: scope.join(' ') });
  res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: clientAuth.client.token_lifetime_s, scope: scope.join(' ') });
}

async function authorizationCodeGrant(req: Request, res: Response) {
  const clientAuth = await authenticateClient(req);
  if (!clientAuth) return errGrant(res, 'invalid_client', 'client authentication failed');
  const { code, redirect_uri, code_verifier } = req.body;
  if (!code || !redirect_uri || !code_verifier) return errGrant(res, 'invalid_request', 'code, redirect_uri, code_verifier required');

  const { rows } = await pool.query(`SELECT * FROM authorization_codes WHERE code_hash = $1`, [sha256(code)]);
  const rec = rows[0];
  if (!rec) return errGrant(res, 'invalid_grant', 'unknown code');
  if (rec.used || new Date(rec.expires_at) < new Date()) return errGrant(res, 'invalid_grant', 'code expired or replayed');
  if (rec.client_id !== clientAuth.clientId) return errGrant(res, 'invalid_grant', 'code bound to another client');
  if (rec.redirect_uri !== redirect_uri) return errGrant(res, 'invalid_grant', 'redirect_uri mismatch');
  if (!verifyPkce(code_verifier, rec.code_challenge)) return errGrant(res, 'invalid_grant', 'PKCE verification failed');

  await pool.query(`UPDATE authorization_codes SET used = true WHERE code_hash = $1`, [sha256(code)]);
  await issueTokens(res, req, rec.user_id, rec.client_id, rec.scope, clientAuth.client.token_lifetime_s, undefined, rec.nonce);
}

async function refreshTokenGrant(req: Request, res: Response) {
  const clientAuth = await authenticateClient(req);
  if (!clientAuth) return errGrant(res, 'invalid_client', 'client authentication failed');
  const { refresh_token } = req.body;
  if (!refresh_token) return errGrant(res, 'invalid_request', 'refresh_token required');

  const { rows } = await pool.query(`SELECT * FROM refresh_tokens WHERE token_hash = $1`, [sha256(refresh_token)]);
  const rt = rows[0];
  if (!rt) return errGrant(res, 'invalid_grant', 'unknown refresh token');
  // replay of a rotated/revoked token => treat whole family as compromised (RFC 9700)
  if (rt.rotated || rt.revoked) {
    await pool.query(`UPDATE refresh_tokens SET revoked = true WHERE family_id = $1`, [rt.family_id]);
    await audit(rt.user_id, clientAuth.clientId, 'refresh_replay_detected', req, { family_id: rt.family_id });
    return errGrant(res, 'invalid_grant', 'token replay detected — family revoked');
  }
  if (rt.client_id !== clientAuth.clientId) return errGrant(res, 'invalid_grant', 'token bound to another client');
  if (new Date(rt.expires_at) < new Date()) return errGrant(res, 'invalid_grant', 'refresh token expired');

  // rotation: single-use, mark old, issue new in the same family
  await pool.query(`UPDATE refresh_tokens SET rotated = true WHERE id = $1`, [rt.id]);
  await issueTokens(res, req, rt.user_id, rt.client_id, rt.scope, clientAuth.client.token_lifetime_s, rt.family_id, rt.nonce);
}

async function issueTokens(res: Response, req: Request, userId: string, clientId: string, scope: string, accessTtlS: number, familyId?: string, nonce?: string | null) {
  const { rows } = await pool.query(
    `SELECT r.code AS role_code FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = $1`, [userId]
  );
  const roles = rows.map((r) => r.role_code);
  const aud = `${clientId}-api`;

  const accessToken = await signToken({ sub: userId, aud, scope, roles, jti: crypto.randomUUID() }, accessTtlS, 'access');
  const idToken = scope.includes('openid')
    ? await signToken({ sub: userId, aud: clientId, roles, ...(nonce ? { nonce } : {}) }, accessTtlS, 'id')
    : undefined;

  const family = familyId || crypto.randomUUID();
  const refreshToken = crypto.randomBytes(32).toString('base64url');
  await pool.query(
    `INSERT INTO refresh_tokens (token_hash, user_id, client_id, family_id, scope, nonce, expires_at)
     VALUES ($1,$2,$3,$4,$5,$6, now() + interval '${config.refreshTtlS} seconds')`,
    [sha256(refreshToken), userId, clientId, family, scope, nonce || null]
  );
  await audit(userId, clientId, 'token_issue', req, { family_id: family });

  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: accessTtlS,
    ...(idToken ? { id_token: idToken } : {}),
    refresh_token: refreshToken,
    scope,
  });
}

export default router;
