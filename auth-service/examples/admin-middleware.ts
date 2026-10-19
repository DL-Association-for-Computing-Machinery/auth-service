/**
 * admin/blog 域资源服务器验签中间件（M3 接入 SDK 示例）。
 *
 * 用法（Express）：
 *   import { requireAuth, createOidcClient } from './admin-middleware';
 *   const oidc = createOidcClient({ issuer: 'http://localhost:4000', audience: 'admin-web-api' });
 *   app.get('/api/dashboard', requireAuth(oidc), handler);
 *
 * 特性：
 * - JWKS 缓存 + kid 自动轮换（10 分钟刷新，kid 未命中强制刷新一次）
 * - 强制 RS256、校验 iss / aud / exp（算法混淆防护）
 */
import { createRemoteJWKSet, jwtVerify, JWTPayload } from 'jose';

export interface OidcClient {
  issuer: string;
  audience: string;
  jwks: ReturnType<typeof createRemoteJWKSet>;
}

export function createOidcClient(opts: { issuer: string; audience: string }): OidcClient {
  return {
    issuer: opts.issuer,
    audience: opts.audience,
    jwks: createRemoteJWKSet(new URL(`${opts.issuer}/.well-known/jwks.json`), { cooldownDuration: 10 * 60 * 1000 }),
  };
}

export async function verifyBearer(oidc: OidcClient, token: string): Promise<JWTPayload> {
  const { payload } = await jwtVerify(token, oidc.jwks, {
    algorithms: ['RS256'],           // algorithm confusion protection
    issuer: oidc.issuer,
    audience: oidc.audience,         // per-domain aud isolation
  });
  return payload;
}

export function requireAuth(oidc: OidcClient) {
  return async (req: any, res: any, next: any) => {
    const auth = req.headers.authorization;
    if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'unauthorized' });
    try {
      req.user = await verifyBearer(oidc, auth.slice(7));
      next();
    } catch (e: any) {
      // 过期 -> 客户端应静默 refresh（用 refresh_token 调 auth /token）；无效 -> 回登录
      const code = e?.code === 'ERR_JWT_EXPIRED' ? 'token_expired' : 'invalid_token';
      res.status(401).json({ error: code });
    }
  };
}

/** 授权码 + PKCE 发起登录（admin 域 Express 路由示例）。 */
export function buildAuthUrl(opts: { issuer: string; clientId: string; redirectUri: string; scope?: string }) {
  const crypto = require('crypto');
  const verifier = crypto.randomBytes(48).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const state = crypto.randomBytes(8).toString('hex');
  const nonce = crypto.randomBytes(8).toString('hex');
  const url = new URL(`${opts.issuer}/authorize`);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', opts.clientId);
  url.searchParams.set('redirect_uri', opts.redirectUri);
  url.searchParams.set('scope', opts.scope || 'openid profile email roles');
  url.searchParams.set('state', state);
  url.searchParams.set('nonce', nonce);
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  // verifier/state/nonce 必须存入用户 session，回调时校验
  return { url: url.toString(), verifier, state, nonce };
}
