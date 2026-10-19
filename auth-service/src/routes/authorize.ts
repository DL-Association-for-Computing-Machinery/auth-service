import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import argon2 from 'argon2';
import { pool, config } from '../config';
import { sha256 } from '../keys';
import { audit } from '../audit';

const router = Router();

interface AuthReq {
  response_type: string;
  client_id: string;
  redirect_uri: string;
  scope: string;
  state: string;
  nonce: string;
  code_challenge: string;
  code_challenge_method: string;
}

/** GET /authorize — validates the request, shows login page, keeps tx in a signed cookie. */
router.get('/authorize', async (req: Request, res: Response) => {
  const q = req.query as unknown as AuthReq;
  const err = (desc: string) => res.status(400).json({ error: 'invalid_request', error_description: desc });

  if (q.response_type !== 'code') return err('response_type must be "code"');
  if (!q.client_id || !q.redirect_uri || !q.state || !q.code_challenge) return err('client_id, redirect_uri, state, code_challenge required');
  if (q.code_challenge_method !== 'S256') return err('PKCE code_challenge_method must be S256 (plain rejected)');
  if (!/^[\w-]{43,128}$/.test(q.code_challenge)) return err('invalid code_challenge');

  const { rows } = await pool.query(
    `SELECT redirect_uris, scopes FROM clients WHERE client_id = $1`, [q.client_id]
  );
  if (!rows.length) return err('unknown client_id');
  // exact string matching only — RFC 9700
  if (!rows[0].redirect_uris.includes(q.redirect_uri)) return err('redirect_uri not registered (exact match required)');
  const scope = q.scope || 'openid';
  const allowed = rows[0].scopes as string[];
  const requested = scope.split(' ');
  if (requested.some((s) => !allowed.includes(s))) return err('scope not allowed for client');

  // stash the transaction for the login POST
  const txId = crypto.randomUUID();
  req.session!.authTx = { ...q, scope, txId };
  res.cookie('auth_tx', txId, { httpOnly: true, sameSite: 'lax', maxAge: 10 * 60 * 1000 });

  res.type('html').send(loginPage(txId, q.client_id));
});

/** POST /login — authenticate user, issue one-time authorization code. */
router.post('/login', async (req: Request, res: Response) => {
  const tx = req.session!.authTx;
  if (!tx || tx.txId !== req.body.txId) return res.status(400).json({ error: 'invalid_request', error_description: 'auth transaction missing/expired' });
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'invalid_request' });

  const { rows } = await pool.query(`SELECT id, password_hash, status FROM users WHERE username = $1`, [username]);
  const user = rows[0];
  const ok = user && user.status === 'active' && (await argon2.verify(user.password_hash, password)).valueOf();
  if (!ok) {
    await audit(user?.id ?? null, tx.client_id, 'login_fail', req, { username });
    return res.status(401).json({ error: 'invalid_credentials' });
  }

  const code = crypto.randomBytes(32).toString('base64url');
  await pool.query(
    `INSERT INTO authorization_codes (code_hash, client_id, user_id, redirect_uri, scope, code_challenge, nonce, expires_at, used)
     VALUES ($1,$2,$3,$4,$5,$6,$7, now() + interval '${config.codeTtlS} seconds', false)`,
    [sha256(code), tx.client_id, user.id, tx.redirect_uri, tx.scope, tx.code_challenge, tx.nonce || null]
  );
  await audit(user.id, tx.client_id, 'code_issue', req, { scope: tx.scope });
  delete req.session!.authTx;
  // never put tokens in URLs — only the one-time code + state
  const redirect = new URL(tx.redirect_uri);
  redirect.searchParams.set('code', code);
  redirect.searchParams.set('state', tx.state);
  res.clearCookie('auth_tx');
  res.redirect(302, redirect.toString());
});

function loginPage(txId: string, clientId: string) {
  return `<!doctype html><html lang="zh"><body style="font-family:sans-serif;max-width:360px;margin:80px auto">
  <h2>统一登录</h2><p>应用：<code>${clientId}</code></p>
  <form method="post" action="/login">
    <input type="hidden" name="txId" value="${txId}">
    <p><input name="username" placeholder="用户名" required style="width:100%;padding:8px"></p>
    <p><input name="password" type="password" placeholder="密码" required style="width:100%;padding:8px"></p>
    <p><button style="width:100%;padding:10px">登录</button></p>
  </form></body></html>`;
}

export default router;
