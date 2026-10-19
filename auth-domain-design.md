# auth 域设计文档与接入规范

> 版本 v0.1 · 2026-10-20 · 状态：设计稿（待评审）  
> 目标：建设独立 auth 域，作为认证中心（Authorization Server / OIDC Provider），为 admin、blog 等域提供统一登录与令牌服务。

---

## 1. 调研结论（OAuth 2.0 / OIDC 2026 现状）

| 结论点           | 说明                                                                                                      |
| ------------- | ------------------------------------------------------------------------------------------------------- |
| 流程选型          | **授权码模式 + PKCE (S256)** 是所有客户端（Web/SPA/移动端，含机密客户端）的唯一推荐流程。Implicit 与密码模式已被 RFC 9700 / OAuth 2.1 废弃，禁止使用 |
| redirect_uri  | **精确字符串匹配**，禁止通配符/前缀匹配；每个环境独立 client 注册                                                                 |
| 防 CSRF/mix-up | 授权请求必须带随机 `state`；OIDC 用 `nonce` 绑定 ID Token；客户端校验响应中的 `iss`                                            |
| Access Token  | **JWT（RS256），有效期 5–15 分钟**，本地验签（jwks_uri + kid），aud 按 API 隔离                                            |
| Refresh Token | **opaque、服务端存储、单次使用 + 轮换**；检测到旧 token 重放 → 吊销整个 token family                                            |
| 撤销            | 提供 `/revoke`（RFC 7009）与 `/introspect`（RFC 7662）；登出/改密即时生效                                               |
| 密钥管理          | 非对称签名（RS256），公钥经 JWKS 发布，用 kid 轮换；严禁算法混淆（只允许 RS256）                                                     |
| 浏览器存储         | refresh token 只放 HttpOnly + Secure + SameSite Cookie 或服务端 session，绝不放 localStorage                      |
| 端点保护          | 发现端点与 JWKS 走 TLS + 限流；日志脱敏（不打 code/token）                                                               |

## 2. 总体架构

```
┌──────────┐     ┌──────────┐
│  admin   │     │   blog   │      ← 资源/应用域（Client）
└────┬─────┘     └────┬─────┘
     │  授权码 + PKCE  │
     ▼                ▼
┌─────────────────────────────┐
│        auth 域 (OIDC Provider)│
│  /authorize /token /revoke   │
│  /userinfo /.well-known/jwks │
└──────────────┬──────────────┘
               ▼
      PostgreSQL (users / roles / clients / tokens)
```

- auth 域是**唯一**持有用户口令与签发令牌的服务；admin/blog 各自注册为 confidential client（client_secret）。
- admin/blog 后端本地验 JWT（RS256）；需要即时吊销语义的操作走 introspect。

## 3. 认证流程（授权码 + PKCE）

1. 用户访问 `admin.example.com`，未登录 → 302 跳转  
   `GET https://auth.example.com/authorize?response_type=code&client_id=admin-web&redirect_uri=https://admin.example.com/auth/callback&scope=openid profile email roles&state=<random>&nonce=<random>&code_challenge=<S256(verifier)>&code_challenge_method=S256`
2. auth 域渲染登录页（口令登录，后续可扩展 MFA/第三方登录），校验用户 → 生成一次性 `code`（TTL 60s，绑定 client + redirect_uri + challenge）
3. 302 回 `redirect_uri?code=...&state=...`；客户端校验 state 后，后端用 `code + code_verifier + client_secret` 调 `POST /token`
4. auth 域返回：
   - `access_token`：JWT，10 分钟，aud = 对应域 API（如 `aud: "admin-api"`）
   - `id_token`：JWT，含 sub / nonce / email / roles
   - `refresh_token`：opaque，7 天，服务端存储，**单次使用轮换**
5. 资源请求带 `Authorization: Bearer <access_token>`；各域后端验签 iss/aud/exp/roles
6. access token 过期 → `grant_type=refresh_token` 换新对；检测到已轮换的旧 RT 重放 → 吊销该用户全部 token family，强制重新登录

## 4. API 设计

| 端点                                  | 方法       | 说明                                                                           |
| ----------------------------------- | -------- | ---------------------------------------------------------------------------- |
| `/.well-known/openid-configuration` | GET      | OIDC 发现                                                                      |
| `/.well-known/jwks.json`            | GET      | 公钥集（kid 轮换）                                                                  |
| `/authorize`                        | GET      | 授权端点（PKCE 必填，S256 only）                                                      |
| `/token`                            | POST     | 换 token（grant_type: authorization_code / refresh_token / client_credentials） |
| `/userinfo`                         | GET      | Bearer token → 用户信息                                                          |
| `/introspect`                       | POST     | 资源服务器内省（需 client 认证）                                                         |
| `/revoke`                           | POST     | 撤销 access/refresh token                                                      |
| `/logout`                           | GET/POST | 登出 + post_logout_redirect_uri（RP-initiated logout）                           |
| `/api/users` CRUD                   | —        | 用户管理（仅 admin client，scope `users:manage`）                                    |
| `/api/roles` CRUD                   | —        | 角色管理（RBAC）                                                                   |
| `/api/clients` CRUD                 | —        | client 注册管理                                                                  |

**错误响应**统一按 RFC 6749：`{"error": "invalid_grant", "error_description": "..."}`；日志与遥测中禁止出现 code/token。

## 5. 数据模型（PostgreSQL）

```sql
users(id uuid pk, username unique, password_hash, email unique,
      status, mfa_secret null, created_at, updated_at)
roles(id uuid pk, code unique, name)                    -- super_admin, admin, editor, user
user_roles(user_id fk, role_id fk, pk(user_id, role_id))
clients(id uuid pk, client_id unique, client_secret_hash,
        name, redirect_uris text[], post_logout_uris text[],
        scopes text[], token_lifetime_s int, is_confidential bool)
authorization_codes(code_hash pk, client_id, user_id, redirect_uri,
        scope, code_challenge, method, nonce, expires_at, used bool)
refresh_tokens(id uuid pk, token_hash, user_id, client_id,
        family_id uuid,     -- 重放检测：一个登录会话一个 family
        rotated bool, revoked bool, expires_at, created_at)
jwks(kid pk, algorithm, public_key_pem, -- 私钥走 KMS/环境变量加密存储
     private_key_encrypted, active bool, created_at)
audit_logs(id, user_id, client_id, event, ip, user_agent, detail jsonb, created_at)
```

要点：code/refresh token 只存哈希；refresh token 带 `family_id` 支持重放全链吊销；口令用 argon2id。

## 6. Token 设计

- **Access Token (JWT/RS256, 10 min)**：  
  `iss=https://auth.example.com, sub=<user_id>, aud=<admin-api|blog-api>, scope, roles[], jti, iat, exp`
- **ID Token (JWT, 10 min)**：含 `nonce`，标准 OIDC claims
- **Refresh Token**：opaque 随机 256bit，仅存哈希，7 天滑动过期，单次轮换
- aud 强隔离：admin 域的 token 不能访问 blog API（反之亦然）

## 7. 安全清单（实现时逐条验收）

- [ ] PKCE 强制 S256，拒绝 plain 与缺失
- [ ] <u>redirect_uri 精确匹配；dev/prod 分开注册 client</u>
- [ ] <u>state + nonce 生成与校验</u>
- [ ] <u>RS256 only；JWKS + kid 轮换（旧公钥保留至旧 token 过期）</u>
- [ ] <u>access token 10 min；refresh 轮换 + 重放检测吊销 family</u>
- [ ] <u>code 60s 一次性；token 一律不进 URL/日志/localStorage</u>
- [ ] <u>登录接口限流 + 账号锁定；审计日志记录 login/refresh/revoke</u>
- [ ] <u>Cookie：HttpOnly + Secure + SameSite=Lax</u>
- [ ] <u>每个域独立 aud，资源端校验 iss/aud/exp/scope</u>

## 8. admin / blog 接入规范

**Client 注册（示例）**

| client_id   | redirect_uri                              | scope                      | aud       |
| ----------- | ----------------------------------------- | -------------------------- | --------- |
| `admin-web` | `https://admin.example.com/auth/callback` | openid profile email roles | admin-api |
| `blog-web`  | `https://blog.example.com/auth/callback`  | openid profile email       | blog-api  |

**接入步骤（每个域 4 步）**

1. 未登录请求 → 302 到 `/authorize`（带 PKCE + state + nonce）
2. 实现 `/auth/callback`：校验 state → `POST /token` 换取三 token
3. refresh token 存服务端（session/加密 Cookie），access token 内存缓存
4. 后端中间件统一验签：JWKS 缓存 + 校验 `iss / aud / exp / scope`；401 时走静默刷新，刷新失败回登录

**登出**：清本地 session → 跳 `/logout?id_token_hint=...&post_logout_redirect_uri=...`

**前端（react-template / SPA）**：推荐 BFF 模式或 `oidc-client-ts`（自动处理 PKCE/state，token 只在内存）。

## 9. 技术栈建议

- 后端：Node.js（NestJS）或 Go —— 与 react-template 前端配套推荐 NestJS + `openid-client` / `node-oidc-provider`（可用成熟库则不自研协议层）
- 数据库：PostgreSQL；后续可加 Redis 缓存 introspect 结果
- 口令：argon2id；JWT：`jose`（强制算法白名单）

## 10. 里程碑

1. **M1**：核心授权链路（authorize/token/jwks/userinfo）+ PostgreSQL 模型
2. **M2**：refresh 轮换 + 重放检测、revoke/introspect、审计日志
3. **M3**：用户/角色/Client 管理后台 API + admin 域接入联调
4. **M4**：blog 域接入 + 登出联动 + 安全清单验收
