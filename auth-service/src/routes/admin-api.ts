import { Router, Request, Response, NextFunction } from 'express';
import argon2 from 'argon2';
import crypto from 'crypto';
import { pool } from '../config';
import { verifyAccessToken } from '../keys';
import { audit } from '../audit';

const router = Router();

/** Bearer auth + scope enforcement for management API. */
const requireScope = (scope: string) => async (req: Request, res: Response, next: NextFunction) => {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'invalid_token' });
  try {
    const claims = (await verifyAccessToken(auth.slice(7))) as any;
    if (!claims.scope?.split(' ').includes(scope)) return res.status(403).json({ error: 'insufficient_scope', required: scope });
    (req as any).claims = claims;
    next();
  } catch {
    return res.status(401).json({ error: 'invalid_token' });
  }
};

// ---------- users ----------
router.get('/api/users', requireScope('users:manage'), async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT u.id, u.username, u.email, u.status, u.created_at,
            COALESCE(array_agg(r.code) FILTER (WHERE r.code IS NOT NULL), '{}') AS roles
     FROM users u LEFT JOIN user_roles ur ON ur.user_id = u.id LEFT JOIN roles r ON r.id = ur.role_id
     GROUP BY u.id ORDER BY u.created_at`
  );
  res.json({ users: rows });
});

router.post('/api/users', requireScope('users:manage'), async (req, res) => {
  const { username, password, email, roles = ['user'] } = req.body;
  if (!username || !password || password.length < 8) return res.status(400).json({ error: 'invalid_request', error_description: 'username and 8+ char password required' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO users (username, password_hash, email) VALUES ($1,$2,$3) RETURNING id, username, email, status`,
      [username, await argon2.hash(password), email || null]
    );
    for (const code of roles) {
      await pool.query(
        `INSERT INTO user_roles (user_id, role_id) SELECT $1, id FROM roles WHERE code = $2 ON CONFLICT DO NOTHING`,
        [rows[0].id, code]
      );
    }
    await audit(rows[0].id, (req as any).claims.sub, 'user_create', req, { username, roles });
    res.status(201).json({ user: rows[0] });
  } catch (e: any) {
    if (e.code === '23505') return res.status(409).json({ error: 'conflict', error_description: 'username/email exists' });
    throw e;
  }
});

router.patch('/api/users/:id', requireScope('users:manage'), async (req, res) => {
  const { email, status, roles, password } = req.body;
  const sets: string[] = []; const vals: any[] = []; let i = 1;
  if (email) { sets.push(`email = $${i++}`); vals.push(email); }
  if (status) { if (!['active', 'locked', 'disabled'].includes(status)) return res.status(400).json({ error: 'invalid_status' }); sets.push(`status = $${i++}`); vals.push(status); }
  if (password) { if (password.length < 8) return res.status(400).json({ error: 'weak_password' }); sets.push(`password_hash = $${i++}`); vals.push(await argon2.hash(password)); }
  if (sets.length) {
    vals.push(req.params.id);
    const { rows } = await pool.query(`UPDATE users SET ${sets.join(', ')}, updated_at = now() WHERE id = $${i} RETURNING id, username, email, status`, vals);
    if (!rows.length) return res.status(404).json({ error: 'not_found' });
    // password/status change => kill all sessions of that user
    if (password || status === 'disabled') await pool.query(`UPDATE refresh_tokens SET revoked = true WHERE user_id = $1 AND revoked = false`, [req.params.id]);
    await audit(req.params.id, (req as any).claims.sub, 'user_update', req, { fields: Object.keys(req.body) });
    return res.json({ user: rows[0] });
  }
  if (Array.isArray(roles)) {
    await pool.query(`DELETE FROM user_roles WHERE user_id = $1`, [req.params.id]);
    for (const code of roles) {
      await pool.query(`INSERT INTO user_roles (user_id, role_id) SELECT $1, id FROM roles WHERE code = $2 ON CONFLICT DO NOTHING`, [req.params.id, code]);
    }
    await audit(req.params.id, (req as any).claims.sub, 'user_roles_update', req, { roles });
    return res.json({ ok: true });
  }
  res.status(400).json({ error: 'invalid_request' });
});

// ---------- roles ----------
router.get('/api/roles', requireScope('users:manage'), async (_req, res) => {
  const { rows } = await pool.query(`SELECT r.id, r.code, r.name, count(ur.user_id) AS members FROM roles r LEFT JOIN user_roles ur ON ur.role_id = r.id GROUP BY r.id ORDER BY r.code`);
  res.json({ roles: rows });
});

// ---------- clients ----------
router.get('/api/clients', requireScope('users:manage'), async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT client_id, name, redirect_uris, post_logout_uris, scopes, token_lifetime_s, is_confidential FROM clients ORDER BY name`
  );
  res.json({ clients: rows });
});

router.post('/api/clients', requireScope('users:manage'), async (req, res) => {
  const { client_id, name, redirect_uris, scopes = ['openid'], token_lifetime_s = 600 } = req.body;
  if (!client_id || !name || !Array.isArray(redirect_uris) || !redirect_uris.length) return res.status(400).json({ error: 'invalid_request' });
  const secret = crypto.randomBytes(24).toString('base64url'); // shown once, stored hashed
  await pool.query(
    `INSERT INTO clients (client_id, client_secret_hash, name, redirect_uris, scopes, token_lifetime_s)
     VALUES ($1,$2,$3,$4,$5,$6)`,
    [client_id, await argon2.hash(secret), name, redirect_uris, scopes, token_lifetime_s]
  );
  await audit(null, client_id, 'client_create', req, { name, redirect_uris });
  res.status(201).json({ client_id, client_secret: secret, note: 'secret shown once — store it now' });
});

export default router;
