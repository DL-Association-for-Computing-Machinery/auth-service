/**
 * blog/admin 域接入完整示例（Express，可复制到各域改造）。
 * 演示：登录跳转 -> 回调换 token -> 会话管理 -> 静默刷新 -> 受保护接口 -> 统一登出。
 *
 * 运行前：auth-service 已启动，blog-web client 已注册（redirect_uri 需包含本服务回调地址）。
 *   ISSUER=http://localhost:4000 CLIENT_ID=blog-web CLIENT_SECRET=blog-web-dev-secret-change-me \
 *   REDIRECT_URI=http://localhost:3001/auth/callback PORT=3001 npx ts-node examples/integration-demo.ts
 */
import express from 'express';
import crypto from 'crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const ISSUER = process.env.ISSUER || 'http://localhost:4000';
const CLIENT_ID = process.env.CLIENT_ID || 'blog-web';
const CLIENT_SECRET = process.env.CLIENT_SECRET || 'blog-web-dev-secret-change-me';
const REDIRECT_URI = process.env.REDIRECT_URI || 'http://localhost:3001/auth/callback';

const jwks = createRemoteJWKSet(new URL(`${ISSUER}/.well-known/jwks.json`), { cooldownDuration: 10 * 60 * 1000 });
const app = express();
app.use(express.urlencoded({ extended: false }));
// cookie parser (minimal) — 必须在路由之前
app.use((req: any, _res, next) => { req.cookies = Object.fromEntries((req.headers.cookie || '').split('; ').map((c) => c.split('=').map(decodeURIComponent) as [string, string]).filter((p) => p.length === 2)); next(); });

// 极简内存会话（生产请用 Redis + 加密 Cookie；refresh token 绝不进 localStorage）
type Session = { userId: string; accessToken: string; refreshToken: string; idToken?: string; expiresAt: number };
const sessions = new Map<string, Session>();
const useCookie = (res: express.Response, sid: string) =>
  res.cookie('app_sid', sid, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax' });

// 1. 登录入口：302 到 auth 域（PKCE S256 + state + nonce）
app.get('/login', (_req, res) => {
  const verifier = crypto.randomBytes(48).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const state = crypto.randomBytes(8).toString('hex');
  const nonce = crypto.randomBytes(8).toString('hex');
  // verifier/state/nonce 存入短期 session cookie（此处用 Map 演示，生产放服务端 session）
  pending.set(state, { verifier, nonce });
  const url = new URL(`${ISSUER}/authorize`);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', CLIENT_ID);
  url.searchParams.set('redirect_uri', REDIRECT_URI);
  url.searchParams.set('scope', 'openid profile email');
  url.searchParams.set('state', state);
  url.searchParams.set('nonce', nonce);
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  res.redirect(url.toString());
});
const pending = new Map<string, { verifier: string; nonce: string }>();

// 2. 回调：校验 state -> 换 token -> 建 session
app.get('/auth/callback', async (req, res) => {
  const { code, state } = req.query as { code?: string; state?: string };
  const tx = state && pending.get(state);
  if (!code || !tx) return res.status(400).send('invalid callback (missing code/state)');
  pending.delete(state);
  const r = await fetch(`${ISSUER}/token`, {
    method: 'POST',
    headers: {
      authorization: `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64')}`,
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI, code_verifier: tx.verifier }),
  });
  if (!r.ok) return res.status(502).json({ error: 'token exchange failed', detail: await r.json() });
  const tokens = await r.json() as { access_token: string; refresh_token: string; id_token: string; expires_in: number };
  const claims = (await jwtVerify(tokens.id_token, jwks, { algorithms: ['RS256'], issuer: ISSUER, audience: CLIENT_ID })).payload;
  if (claims.nonce !== tx.nonce) return res.status(400).send('nonce mismatch');
  const sid = crypto.randomUUID();
  sessions.set(sid, { userId: claims.sub as string, accessToken: tokens.access_token, refreshToken: tokens.refresh_token, idToken: tokens.id_token, expiresAt: Date.now() + tokens.expires_in * 1000 });
  useCookie(res as any, sid);
  res.redirect('/');
});

// 3. 静默刷新：access token 过期自动用 refresh token 轮换
async function ensureFresh(s: Session): Promise<boolean> {
  if (Date.now() < s.expiresAt - 30_000) return true;
  const r = await fetch(`${ISSUER}/token`, {
    method: 'POST',
    headers: {
      authorization: `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64')}`,
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: s.refreshToken }),
  });
  if (!r.ok) return false; // family revoked / expired -> 重新登录
  const t = await r.json() as any;
  s.accessToken = t.access_token;
  s.refreshToken = t.refresh_token;
  s.expiresAt = Date.now() + t.expires_in * 1000;
  return true;
}

// 4. 受保护接口：本地验签（iss/aud/exp，RS256）
app.get('/', async (req, res) => {
  const sid = (req as any).cookies?.app_sid;
  const s = sid && sessions.get(sid);
  if (!s) return res.redirect('/login');
  if (!(await ensureFresh(s))) { sessions.delete(sid); return res.redirect('/login'); }
  const r = await fetch(`${ISSUER}/userinfo`, { headers: { authorization: `Bearer ${s.accessToken}` } });
  res.json({ user: await r.json(), note: 'session valid, token fresh' });
});

// 5. 统一登出：吊销本域 token family（auth 域 /logout），本地 session 清理
app.get('/logout', async (req, res) => {
  const sid = (req as any).cookies?.app_sid;
  const s = sid && sessions.get(sid);
  if (s?.idToken) {
    const url = new URL(`${ISSUER}/logout`);
    url.searchParams.set('id_token_hint', s.idToken);
    res.clearCookie('app_sid');
    sessions.delete(sid);
    return res.redirect(url.toString());
  }
  res.send('logged out');
});

const PORT = Number(process.env.PORT || 3001);
app.listen(PORT, () => console.log(`${CLIENT_ID} demo app on http://localhost:${PORT}`));
