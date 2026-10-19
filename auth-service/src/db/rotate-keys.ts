/**
 * JWKS 轮换：生成新密钥对并置为 active；旧公钥保留（旧 token 验签），
 * 由 --retire 在宽限期后下线旧 kid。
 *
 *   node dist/db/rotate-keys.js            # 生成新 key（旧的继续留在 JWKS 供验签）
 *   node dist/db/rotate-keys.js --retire   # 删除非 active 的旧 key（确保旧 token 已全部过期后执行）
 */
import crypto from 'crypto';
import { generateKeyPair, exportPKCS8, exportSPKI } from 'jose';
import { pool, config } from '../config';

async function main() {
  const retire = process.argv.includes('--retire');
  if (retire) {
    const { rowCount } = await pool.query(`DELETE FROM jwks WHERE active = false RETURNING kid`);
    console.log(`retired ${rowCount} old key(s)`);
  } else {
    // 先把现有 active 下线（仍留在 JWKS 供验签），再插入新 active
    await pool.query(`UPDATE jwks SET active = false WHERE active = true`);
    const { publicKey, privateKey } = await generateKeyPair('RS256', { modulusLength: 2048 });
    const kid = crypto.randomUUID();
    const key = Buffer.from(config.masterKey, 'base64');
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key.subarray(0, 32), iv);
    const enc = Buffer.concat([cipher.update(await exportPKCS8(privateKey), 'utf8'), cipher.final(), cipher.getAuthTag()]);
    await pool.query(
      `INSERT INTO jwks (kid, public_key_pem, private_key_encrypted, active) VALUES ($1,$2,$3,true)`,
      [kid, await exportSPKI(publicKey), iv.toString('base64') + '.' + enc.toString('base64')]
    );
    console.log(`new active kid: ${kid}`);
  }
  await pool.end();
}
main().catch((e) => { console.error(e); process.exit(1); });
