import express, { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { config } from './config';
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
// minimal in-memory session (dev only; prod -> Redis-backed store)
const sessions = new Map<string, Record<string, any>>();
app.use((req, _res, next) => {
  const sid = req.headers.cookie?.match(/auth_sid=([\w-]+)/)?.[1];
  if (sid && sessions.has(sid)) req.session = sessions.get(sid);
  else {
    const newSid = crypto.randomUUID();
    req.session = {};
    sessions.set(newSid, req.session);
    req.headers['x-new-sid'] = newSid;
  }
  next();
});
app.use((req, res, next) => {
  if (req.headers['x-new-sid']) res.cookie('auth_sid', req.headers['x-new-sid'] as string, { httpOnly: true, sameSite: 'lax' });
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
