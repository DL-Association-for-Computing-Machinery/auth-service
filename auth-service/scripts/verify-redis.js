/**
 * Redis 路径双实例验证（需 REDIS_URL 指向可用 Redis）。
 * node verify-redis.js a  -> 实例A：写会话 + 打满限流（10 次）
 * node verify-redis.js b  -> 实例B：读到 A 的会话 + 第 11 次命中被限流
 */
process.env.REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6399';
const phase = process.argv[2];
const { sessionStore, rateStore } = require('../dist/store');

async function main() {
  if (phase === 'a') {
    await sessionStore.set('test-sid', { authTx: { txId: 'tx-1', hello: 'instance-A' } }, 600);
    const results = [];
    for (let i = 0; i < 10; i++) results.push(await rateStore.hit('203.0.113.7', 60000, 10));
    if (!results.every(Boolean)) throw new Error('instance A: first 10 hits should pass');
    console.log('A_OK 10 hits allowed, session written');
    process.exit(0);
  }
  if (phase === 'b') {
    const sess = await sessionStore.get('test-sid');
    if (!sess || sess.authTx?.hello !== 'instance-A') throw new Error('instance B: cannot read session written by A: ' + JSON.stringify(sess));
    const r11 = await rateStore.hit('203.0.113.7', 60000, 10);
    if (r11 !== false) throw new Error('instance B: 11th hit should be denied (shared counter)');
    const other = await rateStore.hit('198.51.100.9', 60000, 10);
    if (other !== true) throw new Error('instance B: other IP should be unaffected');
    console.log('B_OK session shared across instances, 11th hit denied, other IP unaffected');
    process.exit(0);
  }
  throw new Error('usage: node verify-redis.js a|b');
}
main().catch((e) => { console.error('VERIFY FAILED:', e.message); process.exit(1); });
