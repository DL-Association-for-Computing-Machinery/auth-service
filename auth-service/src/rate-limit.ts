/**
 * 登录限流 + 账号锁定（M5）。
 * - 每 IP：滑动窗口 10 次授权/登录请求每分钟（内存实现，单实例；多实例部署换 Redis）
 * - 每账号：连续 5 次口令失败锁定 15 分钟（PG 持久化，重启不丢）
 */
import { Request } from 'express';
import { pool } from './config';

const WINDOW_MS = 60_000;
const IP_MAX = Number(process.env.IP_RATE_MAX || 10);
const FAIL_MAX = 5;
const LOCK_MIN = 15;

const ipHits = new Map<string, number[]>();

export function ipRateLimit(ip: string): boolean {
  const now = Date.now();
  const hits = (ipHits.get(ip) || []).filter((t) => now - t < WINDOW_MS);
  hits.push(now);
  ipHits.set(ip, hits);
  if (ipHits.size > 10_000) { // 防内存膨胀：粗清理
    for (const [k, v] of ipHits) if (!v.some((t) => now - t < WINDOW_MS)) ipHits.delete(k);
  }
  return hits.length <= IP_MAX;
}

export async function isAccountLocked(userId: string): Promise<boolean> {
  const { rows } = await pool.query(
    `SELECT locked_until FROM users WHERE id = $1 AND locked_until > now()`, [userId]
  );
  return rows.length > 0;
}

export async function recordLoginFail(req: Request, userId: string): Promise<boolean> {
  const { rows } = await pool.query(
    `UPDATE users SET failed_attempts = failed_attempts + 1
     WHERE id = $1 RETURNING failed_attempts`,
    [userId]
  );
  const fails = rows[0]?.failed_attempts ?? 0;
  const locked = fails >= FAIL_MAX;
  if (locked) {
    await pool.query(
      `UPDATE users SET locked_until = now() + interval '${LOCK_MIN} minutes' WHERE id = $1`,
      [userId]
    );
  }
  return locked; // true => 本次失败触发锁定
}

export async function resetLoginFails(userId: string): Promise<void> {
  await pool.query(`UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = $1`, [userId]);
}
