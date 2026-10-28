# auth-service

auth 域 OIDC 授权服务器（授权码 + PKCE 模式），为 admin/blog 等域提供统一认证。

## 快速开始

```bash
# 1. 准备 PostgreSQL（默认连接 postgres://postgres:postgres@localhost:5432/auth）
createdb auth

# 2. 安装依赖并构建
npm install
npm run build

# 3. 建表 + 种子数据（admin 用户 + admin-web/blog-web 两个 client）
node dist/db/migrate.js
node dist/db/seed.js

# 4. 启动（默认 http://localhost:4000）
npm start
```

环境变量：`DATABASE_URL`、`AUTH_ISSUER`、`AUTH_PORT`、`AUTH_MASTER_KEY`（32字节 base64，用于加密 JWKS 私钥，生产必设且不可丢失）、`SEED_ADMIN_PASSWORD`、`REDIS_URL`（多实例部署设此项，会话/IP 限流走 Redis 共享；不设则用内存，仅单实例）。

## 多实例部署

- 设 `REDIS_URL` 后，登录会话（`auth_sid`）与 IP 限流计数跨实例共享，可水平扩容（PG 前置负载均衡）
- 账号锁定与审计本就存 PG，多实例天然一致
- Redis 故障时：限流 fail-open（放行并告警）、会话降级告警，不影响 token 签发主链路
- docker compose 已内置 redis:7 服务与 healthcheck

## Docker 部署（推荐）

```bash
# 仓库根目录
export AUTH_MASTER_KEY=$(openssl rand -base64 32)
docker compose up -d --build   # 自带 postgres 17 + 自动迁移
# 首次初始化种子数据（admin 用户 + client 注册）：
docker compose exec auth node dist/db/seed.js
```

## 运维脚本

```bash
npm run rotate-keys           # JWKS 轮换：新密钥生效，旧公钥保留验签
npm run rotate-keys -- --retire   # 宽限期后下线旧 kid（旧 token 全部过期后执行）
npm run cleanup               # 清理过期 code/refresh token/jti 黑名单/审计日志（建议 crontab 每 10 分钟）
```

## 端点

- `GET /.well-known/openid-configuration` — OIDC 发现
- `GET /.well-known/jwks.json` — RS256 公钥
- `GET /authorize` — 授权端点（PKCE S256 强制，redirect_uri 精确匹配）
- `POST /login` — 口令登录 → 发一次性 code（60s）
- `POST /token` — 换 token（authorization_code / refresh_token，refresh 单次轮换 + 重放吊销 family）
- `GET /userinfo` — Bearer 校验用户信息
- `POST /revoke` — 吊销 token（RFC 7009；access 走 jti 黑名单即时失效）
- `POST /introspect` — token 状态内省（RFC 7662）
- `GET/POST /logout` — RP-initiated logout（id_token_hint 吊销 family）
- `GET/POST /api/users`、`/api/roles`、`/api/clients` — 管理 API（scope `users:manage`）

接入 SDK 示例见 `examples/admin-middleware.ts`（验签中间件）与 `examples/integration-demo.ts`（完整回调/刷新/登出流程）。安全验收见 `SECURITY-CHECKLIST.md`。

## admin/blog 接入（伪代码）

```js
// 1. 未登录 -> 302
redirect(`http://localhost:4000/authorize?response_type=code&client_id=admin-web
  &redirect_uri=http://localhost:3000/auth/callback&scope=openid profile email roles
  &state=${state}&nonce=${nonce}&code_challenge=${challenge}&code_challenge_method=S256`)

// 2. callback 校验 state 后后端换取 token
POST http://localhost:4000/token (Basic auth: client_id:client_secret)
  grant_type=authorization_code&code=...&redirect_uri=...&code_verifier=...

// 3. access token (JWT, aud=admin-web-api) 本地验签: /.well-known/jwks.json
// 4. 过期用 refresh_token 轮换
```

## 安全要点（对应设计文档第 7 节）

PKCE 强制 S256；code 一次性 60s；refresh 轮换 + family 吊销；RS256 only；token 只存哈希；精确 redirect_uri；日志脱敏。
