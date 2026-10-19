/**
 * 定期清理任务（建议 crontab 每 10 分钟）：
 *   node dist/db/cleanup.js
 * 清理：过期 authorization_codes、过期/已吊销 refresh_tokens、过期的 revoked_jtis。
 */
import { pool } from '../config';

async function main() {
  const c1 = await pool.query(`DELETE FROM authorization_codes WHERE expires_at < now() - interval '1 day'`);
  const c2 = await pool.query(`DELETE FROM refresh_tokens WHERE expires_at < now() - interval '30 days' OR (revoked = true AND expires_at < now())`);
  const c3 = await pool.query(`DELETE FROM revoked_jtis WHERE expires_at < now()`);
  const c4 = await pool.query(`DELETE FROM audit_logs WHERE created_at < now() - interval '180 days'`);
  console.log(`cleaned: codes=${c1.rowCount} refresh=${c2.rowCount} jti=${c3.rowCount} audit=${c4.rowCount}`);
  await pool.end();
}
main().catch((e) => { console.error(e); process.exit(1); });
