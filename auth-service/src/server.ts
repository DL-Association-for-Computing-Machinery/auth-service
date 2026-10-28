import express, { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { config } from './config';
import { sessionStore, SESSION_TTL_S } from './store';
import authorizeRouter from './routes/authorize';
import tokenRouter from './routes/token';
import oidcRouter from './routes/oidc';
import managementRouter from './routes/management';
import adminApiRouter from './routes/admin-api';

declare module 'express-serve-static-core' {
  interface Request {
    session?: Record<string, any>;
  }
}

const app = express();
app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: false }));
// 会话走统一 store（memory 或 Redis，见 store.ts），多实例共享
app.use(async (req: Request, res: Response, next: NextFunction) => {
  const sid = req.headers.cookie?.match(/auth_sid=([\w-]+)/)?.[1];
  const loaded = sid ? await sessionStore.get(sid) : null;
  if (sid && loaded) {
    req.session = loaded;
  } else {
    req.session = {};
    req.headers['x-new-sid'] = crypto.randomUUID();
  }
  // 响应结束时持久化：路由处理中的变更此刻已定型
  const currentSid = () => (req.headers['x-new-sid'] as string) || (sid as string);
  res.on('finish', () => {
    const s = req.session!;
    if (Object.keys(s).length > 0) {
      void sessionStore.set(currentSid(), s, SESSION_TTL_S);
    } else if (!req.headers['x-new-sid'] && sid) {
      void sessionStore.del(sid); // 会话已清空（如 authTx 消费完毕），清理旧键
    }
  });
  next();
});
app.use((req, res, next) => {
  if (req.headers['x-new-sid']) res.cookie('auth_sid', req.headers['x-new-sid'] as string, { httpOnly: true, sameSite: 'lax', secure: config.issuer.startsWith('https') });
  next();
});

app.use(authorizeRouter);
app.use(tokenRouter);
app.use(oidcRouter);
app.use(managementRouter);
app.use(adminApiRouter);

app.use((_req: Request, res: Response) => res.status(404).json({ error: 'not_found' }));
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  // never leak tokens/codes in logs
  console.error('[auth]', err.message);
  res.status(500).json({ error: 'server_error' });
});

app.listen(config.port, () => console.log(`auth service listening on ${config.issuer}`));
