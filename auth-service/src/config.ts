import { Pool } from 'pg';
import crypto from 'crypto';

export const config = {
  issuer: process.env.AUTH_ISSUER || 'http://localhost:4000',
  port: Number(process.env.AUTH_PORT || 4000),
  databaseUrl: process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:5432/auth',
  // code TTL 60s (one-time), access token from client record (default 10 min), refresh 7 days
  codeTtlS: 60,
  refreshTtlS: 7 * 24 * 3600,
  masterKey: process.env.AUTH_MASTER_KEY || crypto.randomBytes(32).toString('base64'),
};

export const pool = new Pool({ connectionString: config.databaseUrl });
