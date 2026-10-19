/**
 * E2E smoke test: embedded postgres -> migrate -> seed -> full auth code + PKCE flow.
 * Run: node dist/smoke-test.js
 */
const _ep: any = require('embedded-postgres');
const EmbeddedPostgres: any = _ep.default ?? _ep;
import crypto from 'crypto';
import http from 'http';
import { spawn } from 'child_process';

const PORT = 4100;

type Res = { status: number; headers: any; body: string; setCookie?: string[] };

async function req(method: string, path: string, opts: { body?: any; headers?: Record<string, string> } = {}): Promise<Res> {
  const { body, headers = {} } = opts;
  return new Promise<Res>((resolve, reject) => {
    const isJson = headers['content-type'] === 'application/json';
    const data = body ? (isJson ? JSON.stringify(body) : new URLSearchParams(body).toString()) : null;
    const r = http.request({
      host: 'localhost', port: PORT, path, method,
      headers: {
        ...(data ? { 'content-type': isJson ? 'application/json' : 'application/x-www-form-urlencoded', 'content-length': Buffer.byteLength(data) } : {}),
        ...headers,
      },
    }, (res) => {
      let out = '';
      res.on('data', (c) => (out += c));
      res.on('end', () => resolve({ status: res.statusCode!, headers: res.headers, body: out, setCookie: res.headers['set-cookie'] }));
    });
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}

function b64url(buf: Buffer) { return buf.toString('base64url'); }

async function main() {
  // 1. embedded postgres
  const pg = new EmbeddedPostgres({
    databaseDir: './.smoke-pg',
    user: 'postgres', password: 'postgres', port: 5544, persistent: false,
  });
  await pg.initialise();
  await pg.start();
  await pg.createDatabase('auth');

  // 2. migrate + seed + start server (child processes using compiled dist)
  process.env.DATABASE_URL = 'postgres://postgres:postgres@localhost:5544/auth';
  process.env.AUTH_PORT = String(PORT);
  process.env.AUTH_ISSUER = `http://localhost:${PORT}`;
  process.env.IP_RATE_MAX = '200';
  const { pool } = await import('./config');
  const fs = await import('fs');
  for (const f of fs.readdirSync('migrations').filter((f) => f.endsWith('.sql')).sort()) {
    await pool.query(fs.readFileSync('migrations/' + f, 'utf8'));
  }

  await pool.end();

  const run = (js: string) => spawn(process.execPath, [js], { env: process.env, stdio: 'inherit' });
  await new Promise<void>((res, rej) => { const p = run('dist/db/seed.js'); p.on('exit', (c) => (c === 0 ? res() : rej(new Error('seed failed')))); });
  const server = run('dist/server.js');
  await new Promise((r) => setTimeout(r, 1500));

  // 3. full authorization code + PKCE flow
  const verifier = b64url(crypto.randomBytes(48));
  const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
  const state = crypto.randomBytes(8).toString('hex');

  const a1 = await req('GET', `/authorize?response_type=code&client_id=admin-web&redirect_uri=http://localhost:3000/auth/callback&scope=openid%20profile%20email%20roles&state=${state}&nonce=abc&code_challenge=${challenge}&code_challenge_method=S256`);
  if (a1.status !== 200 || !a1.body.includes('统一登录')) throw new Error('authorize failed: ' + a1.status);
  console.log('✓ /authorize returns login page');

  const txId = a1.body.match(/name="txId" value="([\w-]+)"/)![1];
  const sidCookie = a1.setCookie!.map((c) => c.split(';')[0]).join('; ');
  const a2 = await req('POST', '/login', { body: { txId, username: 'admin', password: 'ChangeMe#2026' }, headers: { cookie: sidCookie } });
  if (a2.status !== 302) throw new Error('login failed: ' + a2.status + ' ' + a2.body);
  const loc = new URL(a2.headers.location);
  const code = loc.searchParams.get("code")!;
  if (loc.searchParams.get("state")! !== state || !code) throw new Error('state/code missing in redirect');
  console.log('✓ /login issues one-time code, state echoed');

  // 3b. wrong password
  const a3 = await req('GET', `/authorize?response_type=code&client_id=admin-web&redirect_uri=http://localhost:3000/auth/callback&scope=openid%20profile%20email%20roles&state=${state}&nonce=abc&code_challenge=${challenge}&code_challenge_method=S256`);
  const tx2 = a3.body.match(/name="txId" value="([\w-]+)"/)![1];
  const a4 = await req('POST', '/login', { body: { txId: tx2, username: 'admin', password: 'wrong' }, headers: { cookie: (a3.setCookie || []).map((c) => c.split(';')[0]).join('; ') } });
  if (a4.status !== 401) throw new Error('wrong password should 401');
  console.log('✓ wrong password rejected');

  // 4. token exchange with client auth + PKCE
  const basic = Buffer.from('admin-web:admin-web-dev-secret-change-me').toString('base64');
  const t1 = await req('POST', '/token', { body: { grant_type: 'authorization_code', code, redirect_uri: 'http://localhost:3000/auth/callback', code_verifier: verifier }, headers: { authorization: `Basic ${basic}` } });
  if (t1.status !== 200) throw new Error('token failed: ' + t1.status + ' ' + t1.body);
  const tokens = JSON.parse(t1.body);
  console.log('✓ /token issues access_token + refresh_token + id_token');

  // 5. userinfo
  const u1 = await req('GET', '/userinfo', { headers: { authorization: `Bearer ${tokens.access_token}` } });
  if (u1.status !== 200 || !JSON.parse(u1.body).username) throw new Error('userinfo failed: ' + u1.body);
  console.log('✓ /userinfo:', u1.body);

  // 6. code replay must fail
  const t2 = await req('POST', '/token', { body: { grant_type: 'authorization_code', code, redirect_uri: 'http://localhost:3000/auth/callback', code_verifier: verifier }, headers: { authorization: `Basic ${basic}` } });
  if (t2.status !== 400 || !JSON.parse(t2.body).error.includes('invalid_grant')) throw new Error('code replay not rejected');
  console.log('✓ code replay rejected (one-time)');

  // 7. refresh rotation + replay detection
  const r1 = await req('POST', '/token', { body: { grant_type: 'refresh_token', refresh_token: tokens.refresh_token }, headers: { authorization: `Basic ${basic}` } });
  if (r1.status !== 200) throw new Error('refresh failed: ' + r1.body);
  const tokens2 = JSON.parse(r1.body);
  if (tokens2.refresh_token === tokens.refresh_token) throw new Error('refresh token not rotated');
  console.log('✓ refresh token rotated');

  const r2 = await req('POST', '/token', { body: { grant_type: 'refresh_token', refresh_token: tokens.refresh_token }, headers: { authorization: `Basic ${basic}` } });
  if (r2.status !== 400) throw new Error('replay of rotated refresh token should fail');
  console.log('✓ refresh replay detected → family revoked');

  const r3 = await req('POST', '/token', { body: { grant_type: 'refresh_token', refresh_token: tokens2.refresh_token }, headers: { authorization: `Basic ${basic}` } });
  if (r3.status !== 400) throw new Error('family should be revoked after replay');
  console.log('✓ whole token family revoked after replay');

  // 8. PKCE wrong verifier
  const a5 = await req('GET', `/authorize?response_type=code&client_id=admin-web&redirect_uri=http://localhost:3000/auth/callback&scope=openid&state=${state}&nonce=abc&code_challenge=${challenge}&code_challenge_method=S256`);
  const tx3 = a5.body.match(/name="txId" value="([\w-]+)"/)![1];
  const a6 = await req('POST', '/login', { body: { txId: tx3, username: 'admin', password: 'ChangeMe#2026' }, headers: { cookie: (a5.setCookie || []).map((c) => c.split(';')[0]).join('; ') } });
  const code2 = new URL(a6.headers.location).searchParams.get('code')!;
  const t3 = await req('POST', '/token', { body: { grant_type: 'authorization_code', code: code2, redirect_uri: 'http://localhost:3000/auth/callback', code_verifier: b64url(crypto.randomBytes(48)) }, headers: { authorization: `Basic ${basic}` } });
  if (t3.status !== 400) throw new Error('wrong PKCE verifier should fail');
  console.log('✓ PKCE wrong verifier rejected');

  // 9. discovery + jwks
  const d1 = await req('GET', '/.well-known/openid-configuration');
  const j1 = await req('GET', '/.well-known/jwks.json');
  if (d1.status !== 200 || j1.status !== 200 || !JSON.parse(j1.body).keys.length) throw new Error('discovery/jwks failed');
  console.log('✓ discovery + jwks published');

  // --- M2: revoke / introspect / logout ---
  // 10. get a fresh token set
  const a7 = await req('GET', `/authorize?response_type=code&client_id=admin-web&redirect_uri=http://localhost:3000/auth/callback&scope=openid%20profile%20email%20roles&state=${state}&nonce=abc&code_challenge=${challenge}&code_challenge_method=S256`);
  const tx4 = a7.body.match(/name="txId" value="([\w-]+)"/)![1];
  const a8 = await req('POST', '/login', { body: { txId: tx4, username: 'admin', password: 'ChangeMe#2026' }, headers: { cookie: a7.setCookie!.map((c: string) => c.split(';')[0]).join('; ') } });
  const code3 = new URL(a8.headers.location).searchParams.get('code')!;
  const t4 = await req('POST', '/token', { body: { grant_type: 'authorization_code', code: code3, redirect_uri: 'http://localhost:3000/auth/callback', code_verifier: verifier }, headers: { authorization: `Basic ${basic}` } });
  const tok3 = JSON.parse(t4.body);

  // 11. introspect: access active:true, refresh active:true
  const i1 = await req('POST', '/introspect', { body: { token: tok3.access_token }, headers: { authorization: `Basic ${basic}` } });
  if (JSON.parse(i1.body).active !== true) throw new Error('introspect access should be active: ' + i1.body);
  const i2 = await req('POST', '/introspect', { body: { token: tok3.refresh_token }, headers: { authorization: `Basic ${basic}` } });
  if (JSON.parse(i2.body).active !== true) throw new Error('introspect refresh should be active');
  console.log('✓ introspect access + refresh active');

  // 12. revoke access token -> introspect active:false (immediate revocation)
  const v1 = await req('POST', '/revoke', { body: { token: tok3.access_token }, headers: { authorization: `Basic ${basic}` } });
  if (v1.status !== 200) throw new Error('revoke failed');
  const i3 = await req('POST', '/introspect', { body: { token: tok3.access_token }, headers: { authorization: `Basic ${basic}` } });
  if (JSON.parse(i3.body).active !== false) throw new Error('revoked access should be inactive');
  console.log('✓ access token revoked immediately (jti blacklist)');

  // 13. logout with id_token_hint -> refresh family revoked
  const l1 = await req('GET', `/logout?id_token_hint=${encodeURIComponent(tok3.id_token)}`);
  if (l1.status !== 200) throw new Error('logout failed: ' + l1.status);
  const i4 = await req('POST', '/introspect', { body: { token: tok3.refresh_token }, headers: { authorization: `Basic ${basic}` } });
  if (JSON.parse(i4.body).active !== false) throw new Error('refresh should be revoked after logout');
  console.log('✓ RP-initiated logout revoked token family');

  // 14. open-redirect protection: unregistered post_logout uri must NOT redirect
  const l2 = await req('GET', `/logout?id_token_hint=${encodeURIComponent(tok3.id_token)}&post_logout_redirect_uri=${encodeURIComponent('https://evil.example.com')}`);
  if (l2.status === 302) throw new Error('open redirect via post_logout_redirect_uri!');
  console.log('✓ unregistered post_logout_redirect_uri rejected');

  // --- M3: management API ---
  // 15. scope enforcement: blog-web has no users:manage -> 403; wrong bearer -> 401
  const m0 = await req('GET', '/api/users', { headers: { authorization: 'Bearer garbage' } });
  if (m0.status !== 401) throw new Error('management API should 401 without valid token');
  console.log('✓ management API rejects invalid bearer');

  // 16. login as admin again, use access token (roles + users:manage scope) to manage users
  const a9 = await req('GET', `/authorize?response_type=code&client_id=admin-web&redirect_uri=http://localhost:3000/auth/callback&scope=openid%20profile%20email%20roles%20users:manage&state=${state}&nonce=abc&code_challenge=${challenge}&code_challenge_method=S256`);
  const tx5 = a9.body.match(/name="txId" value="([\w-]+)"/)![1];
  const a10 = await req('POST', '/login', { body: { txId: tx5, username: 'admin', password: 'ChangeMe#2026' }, headers: { cookie: a9.setCookie!.map((c: string) => c.split(';')[0]).join('; ') } });
  const code4 = new URL(a10.headers.location).searchParams.get('code')!;
  const t5 = await req('POST', '/token', { body: { grant_type: 'authorization_code', code: code4, redirect_uri: 'http://localhost:3000/auth/callback', code_verifier: verifier }, headers: { authorization: `Basic ${basic}` } });
  const tok4 = JSON.parse(t5.body);

  const m1 = await req('GET', '/api/users', { headers: { authorization: `Bearer ${tok4.access_token}` } });
  if (m1.status !== 200 || !JSON.parse(m1.body).users.length) throw new Error('list users failed: ' + m1.body);
  console.log('✓ list users via management API');

  const m2 = await req('POST', '/api/users', { body: { username: 'editor1', password: 'Editor#2026!', email: 'e1@example.com', roles: ['editor'] }, headers: { authorization: `Bearer ${tok4.access_token}`, 'content-type': 'application/json' } });
  if (m2.status !== 201) throw new Error('create user failed: ' + m2.body);
  console.log('✓ create user (editor1) via management API');

  // 17. new user can login and gets editor role
  const a11 = await req('GET', `/authorize?response_type=code&client_id=blog-web&redirect_uri=http://localhost:3001/auth/callback&scope=openid%20profile%20email&state=${state}&nonce=abc&code_challenge=${challenge}&code_challenge_method=S256`);
  const tx6 = a11.body.match(/name="txId" value="([\w-]+)"/)![1];
  const a12 = await req('POST', '/login', { body: { txId: tx6, username: 'editor1', password: 'Editor#2026!' }, headers: { cookie: a11.setCookie!.map((c: string) => c.split(';')[0]).join('; ') } });
  const code5 = new URL(a12.headers.location).searchParams.get('code')!;
  const blogBasic = Buffer.from('blog-web:blog-web-dev-secret-change-me').toString('base64');
  const t6 = await req('POST', '/token', { body: { grant_type: 'authorization_code', code: code5, redirect_uri: 'http://localhost:3001/auth/callback', code_verifier: verifier }, headers: { authorization: `Basic ${blogBasic}` } });
  const tok5 = JSON.parse(t6.body);
  if (!tok5.access_token) throw new Error('editor1 login via blog-web failed: ' + t6.body);
  console.log('✓ newly created user logs in via blog-web client');

  // 18. aud isolation: blog token cannot hit admin management API (403/401), and admin token aud != blog
  const m3 = await req('GET', '/api/users', { headers: { authorization: `Bearer ${tok5.access_token}` } });
  if (m3.status === 200) throw new Error('blog token must not access management API');
  console.log('✓ aud/scope isolation enforced (blog token rejected on management API)');

  // 19. create client via API
  const m4 = await req('POST', '/api/clients', { body: { client_id: 'shop-web', name: 'Shop', redirect_uris: ['http://localhost:3002/auth/callback'], scopes: ['openid', 'profile'] }, headers: { authorization: `Bearer ${tok4.access_token}`, 'content-type': 'application/json' } });
  if (m4.status !== 201 || !JSON.parse(m4.body).client_secret) throw new Error('create client failed: ' + m4.body);
  console.log('✓ register new client (shop-web) via management API');

  // --- M5: brute-force lockout ---
  // (edit1 login failures: use fresh authorize txs)
  const doLogin = async (password: string) => {
    const a = await req('GET', `/authorize?response_type=code&client_id=blog-web&redirect_uri=http://localhost:3001/auth/callback&scope=openid&state=${state}&nonce=abc&code_challenge=${challenge}&code_challenge_method=S256`);
    const tx = a.body.match(/name="txId" value="([\w-]+)"/)![1];
    return req('POST', '/login', { body: { txId: tx, username: 'editor1', password }, headers: { cookie: a.setCookie!.map((c: string) => c.split(';')[0]).join('; ') } });
  };
  let last;
  for (let i = 0; i < 5; i++) {
    last = await doLogin('totally-wrong');
    if (i < 4 && last.status !== 401) throw new Error(`fail ${i + 1} should be 401, got ${last.status}`);
  }
  if (last!.status !== 423) throw new Error('5th failure should trigger 423 lockout, got ' + last!.status);
  console.log('✓ 5 consecutive failures lock the account (423)');
  const l3 = await doLogin('Editor#2026!'); // 正确口令也应被拒
  if (l3.status !== 423) throw new Error('locked account must reject correct password too');
  console.log('✓ locked account rejects even correct password');

  // admin 解锁后恢复正常（通过管理 API 恢复 status 触发 reset？这里直接用 PATCH status=active 不清锁，验证管理员改密吊销路径已覆盖；解锁走 DB）
  server.kill();
  await pg.stop();
  fs.rmSync('.smoke-pg', { recursive: true, force: true });
  console.log('\nALL SMOKE TESTS PASSED');
  process.exit(0);
}

main().catch((e) => { console.error('SMOKE FAILED:', e.message); process.exit(1); });
