# 安全清单验收（设计文档第 7 节对照）

状态：2026-10-20 · 自动化冒烟测试（`npm run build && node dist/smoke-test.js`）覆盖。

| # | 控制项 | 状态 | 验证方式 |
|---|---|---|---|
| 1 | PKCE 强制 S256，拒绝 plain/缺失 | ✅ | `/authorize` 校验 `code_challenge_method === 'S256'`；wrong verifier 换 token 被拒（测试✓） |
| 2 | redirect_uri 精确匹配；环境分开注册 | ✅ | 未注册 URI 返回 400（测试✓）；client 表按 dev/prod URI 注册 |
| 3 | state + nonce 生成与校验 | ✅ | 回调回显 state（测试✓）；示例 App 校验 id_token nonce |
| 4 | RS256 only；JWKS + kid 轮换 | ✅ | jose 验签锁定 `algorithms: ['RS256']`；jwks 表支持多 kid，旧公钥保留 |
| 5 | access 10min；refresh 轮换 + 重放吊销 family | ✅ | 轮换、重放检测、family 全吊销（测试✓✓✓） |
| 6 | code 60s 一次性；token 不进 URL/日志/localStorage | ✅ | code 重放被拒（测试✓）；日志只记哈希与事件；示例 App refresh token 存服务端 session |
| 7 | 登录限流 + 账号锁定；审计日志 | ⚠️ 部分 | 审计日志已埋点（login/login_fail/token_issue/revoke/logout）；**限流/锁定待接入（M4 遗留，建议 auth 域前置 Redis 限流中间件）** |
| 8 | Cookie HttpOnly + Secure + SameSite | ✅ | auth_tx/auth_sid/app_sid 均 HttpOnly+SameSite；Secure 由 NODE_ENV=production 控制 |
| 9 | aud 隔离 + 资源端校验 iss/aud/exp/scope | ✅ | blog token 调管理 API 被拒（测试✓）；SDK/中间件强制校验 |
| 10 | 即时吊销语义 | ✅ | /revoke jti 黑名单 + /introspect（测试✓）；改密/禁用用户吊销其全部会话 |

**遗留事项（上线前）**
- 登录限流/账号锁定（Redis）
- 生产部署：HTTPS 强制、AUTH_MASTER_KEY 用 KMS 管理、session 改 Redis
- JWKS 定期轮换运维脚本
- 审计日志异常模式告警（refresh 重放、scope 提升等）
