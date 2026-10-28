/**
 * 多实例共享存储层（M6）。
 * - 未设 REDIS_URL：内存实现（单实例开发用，行为与旧版完全一致）
 * - 设 REDIS_URL：Redis 实现（会话 + IP 限流跨实例共享）
 * 故障策略：Redis 不可用时，限流 fail-open（放行并告警），会话读写降级告警，
 * 不拖垮认证主链路；账号锁定/审计本就走 PG，天然多实例安全。
 */
import crypto from 'crypto';

export interface SessionStore {
  get(sid: string): Promise<Record<string, any> | null>;
  set(sid: string, data: Record<string, any>, ttlS: number): Promise<void>;
  del(sid: string): Promise<void>;
}

export interface RateStore {
  /** 记一次命中；返回 true = 允许（窗口内计数 <= max） */
  hit(key: string, windowMs: number, max: number): Promise<boolean>;
}

export const SESSION_TTL_S = 24 * 3600;

// ---------- memory（单实例，行为与旧版一致） ----------
const memSessions = new Map<string, Record<string, any>>();

const memorySessionStore: SessionStore = {
  async get(sid) { return memSessions.get(sid) ?? null; },
  async set(sid, data, ttlS) {
    memSessions.set(sid, data);
    if (memSessions.size > 50_000) { // 防内存膨胀
      for (const k of memSessions.keys()) { if (memSessions.size <= 40_000) break; memSessions.delete(k); }
    }
    void ttlS;
  },
  async del(sid) { memSessions.delete(sid); },
};

const memHits = new Map<string, number[]>();
const memoryRateStore: RateStore = {
  async hit(key, windowMs, max) {
    const now = Date.now();
    const hits = (memHits.get(key) || []).filter((t) => now - t < windowMs);
    hits.push(now);
    memHits.set(key, hits);
    if (memHits.size > 10_000) {
      for (const [k, v] of memHits) if (!v.some((t) => now - t < windowMs)) memHits.delete(k);
    }
    return hits.length <= max;
  },
};

// ---------- redis（多实例共享） ----------
function createRedis() {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const Redis = require('ioredis');
  const client = new Redis(process.env.REDIS_URL as string, { maxRetriesPerRequest: 1 });
  client.on('error', (e: Error) => console.error('[auth] redis error:', e.message));
  return client;
}

let redis: any = null;
if (process.env.REDIS_URL) {
  redis = createRedis();
  redis.on('ready', () => console.log('[auth] redis connected:', process.env.REDIS_URL));
}

const redisSessionStore: SessionStore = {
  // ioredis 会在连接建立前排队命令（enableReadyQueue），无需自行判断 ready；
  // 连接失败/超时由 maxRetriesPerRequest:1 抛错，走 catch 降级
  async get(sid) {
    try {
      const raw = await redis.get(`sess:${sid}`);
      return raw ? JSON.parse(raw) : null;
    } catch (e: any) {
      console.error('[auth] session get failed (degraded):', e.message);
      return null;
    }
  },
  async set(sid, data, ttlS) {
    try { await redis.set(`sess:${sid}`, JSON.stringify(data), 'EX', ttlS); }
    catch (e: any) { console.error('[auth] session set failed (degraded):', e.message); }
  },
  async del(sid) {
    try { await redis.del(`sess:${sid}`); } catch (e: any) { console.error('[auth] session del failed:', e.message); }
  },
};

const redisRateStore: RateStore = {
  async hit(key, windowMs, max) {
    try {
      const bucket = Math.floor(Date.now() / windowMs); // 固定窗口，跨实例一致
      const k = `rl:${key}:${bucket}`;
      const n = await redis.incr(k);
      if (n === 1) await redis.pexpire(k, windowMs * 2);
      return n <= max;
    } catch (e: any) {
      console.error('[auth] rate limit failed (fail-open):', e.message);
      return true;
    }
  },
};

export const sessionStore: SessionStore = redis ? redisSessionStore : memorySessionStore;
export const rateStore: RateStore = redis ? redisRateStore : memoryRateStore;

export const randomSid = () => crypto.randomUUID();
