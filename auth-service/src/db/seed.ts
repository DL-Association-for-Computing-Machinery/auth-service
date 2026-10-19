import argon2 from 'argon2';
import { pool } from '../config';

/** Seed: roles + admin user + two client registrations (admin-web, blog-web). */
async function seed() {
  const adminPass = process.env.SEED_ADMIN_PASSWORD || 'ChangeMe#2026';
  for (const [code, name] of [['super_admin', '超级管理员'], ['admin', '管理员'], ['editor', '编辑'], ['user', '普通用户']]) {
    await pool.query(`INSERT INTO roles (code, name) VALUES ($1,$2) ON CONFLICT (code) DO NOTHING`, [code, name]);
  }

  const { rows: admin } = await pool.query(
    `INSERT INTO users (username, password_hash, email) VALUES ('admin', $1, 'admin@example.com')
     ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash RETURNING id`,
    [await argon2.hash(adminPass)]
  );
  await pool.query(
    `INSERT INTO user_roles (user_id, role_id)
     SELECT $1, id FROM roles WHERE code = 'super_admin' ON CONFLICT DO NOTHING`, [admin[0].id]
  );

  const clients: Array<[string, string, string[], string[], string[]]> = [
    ['admin-web', 'Admin 管理后台', ['http://localhost:3000/auth/callback'], ['https://admin.example.com/auth/callback'], ['openid', 'profile', 'email', 'roles', 'users:manage']],
    ['blog-web', 'Blog 博客', ['http://localhost:3001/auth/callback'], ['https://blog.example.com/auth/callback'], ['openid', 'profile', 'email']],
  ];
  for (const [clientId, name, devUris, prodUris, scopes] of clients) {
    const secret = process.env[`SEED_${clientId.toUpperCase().replace(/-/g, '_')}_SECRET`] || `${clientId}-dev-secret-change-me`;
    await pool.query(
      `INSERT INTO clients (client_id, client_secret_hash, name, redirect_uris, post_logout_uris, scopes)
       VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT (client_id) DO UPDATE SET redirect_uris = EXCLUDED.redirect_uris, scopes = EXCLUDED.scopes`,
      [clientId, await argon2.hash(secret), name, [...devUris, ...prodUris], [], scopes]
    );
    console.log(`client ${clientId} secret (dev): ${secret}`);
  }
  console.log(`admin user password: ${adminPass}`);
  await pool.end();
}
seed().catch((e) => { console.error(e); process.exit(1); });
