import { pool } from './config';

export async function audit(userId: string | null, clientId: string | null, event: string, req: any, detail: object = {}) {
  await pool.query(
    `INSERT INTO audit_logs (user_id, client_id, event, ip, user_agent, detail) VALUES ($1,$2,$3,$4,$5,$6)`,
    [userId, clientId, event, req?.ip || null, req?.headers?.['user-agent'] || null, JSON.stringify(detail)]
  );
}
