import fs from 'fs';
import path from 'path';
import { pool } from '../config';

async function migrate() {
  const dir = path.join(__dirname, '..', '..', 'migrations');
  await pool.query(`CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz DEFAULT now())`);
  for (const f of fs.readdirSync(dir).filter((f) => f.endsWith('.sql')).sort()) {
    const { rows } = await pool.query(`SELECT 1 FROM schema_migrations WHERE name = $1`, [f]);
    if (rows.length) continue;
    console.log('applying', f);
    await pool.query(fs.readFileSync(path.join(dir, f), 'utf8'));
    await pool.query(`INSERT INTO schema_migrations (name) VALUES ($1)`, [f]);
  }
  await pool.end();
}
migrate().catch((e) => { console.error(e); process.exit(1); });
