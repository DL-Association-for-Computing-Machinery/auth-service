import { SignJWT, jwtVerify, importPKCS8, importSPKI, generateKeyPair, exportPKCS8, exportSPKI, exportJWK } from 'jose';
import crypto from 'crypto';
import { pool, config } from './config';

let signingKey: { kid: string; privateKey: crypto.KeyObject; publicKey: crypto.KeyObject } | null = null;

/** Load active RSA key from DB, or generate one. Returns signing context. */
export async function loadSigningKey() {
  if (signingKey) return signingKey;
  const { rows } = await pool.query(
    `SELECT kid, public_key_pem, private_key_encrypted FROM jwks WHERE active = true ORDER BY created_at DESC LIMIT 1`
  );
  if (rows.length) {
    const pem = decrypt(rows[0].private_key_encrypted);
    const privateKey = crypto.createPrivateKey(pem) as crypto.KeyObject;
    const publicKey = crypto.createPublicKey(rows[0].public_key_pem) as crypto.KeyObject;
    signingKey = { kid: rows[0].kid, privateKey, publicKey };
  } else {
    const { publicKey, privateKey } = await generateKeyPair('RS256', { modulusLength: 2048 });
    const kid = crypto.randomUUID();
    await pool.query(
      `INSERT INTO jwks (kid, public_key_pem, private_key_encrypted, active) VALUES ($1,$2,$3,true)`,
      [kid, await exportSPKI(publicKey), encrypt(await exportPKCS8(privateKey))]
    );
    signingKey = { kid, privateKey: privateKey as crypto.KeyObject, publicKey: publicKey as crypto.KeyObject };
  }
  return signingKey;
}

function encrypt(plain: string): string {
  const iv = crypto.randomBytes(12);
  const key = Buffer.from(config.masterKey, 'base64');
  const cipher = crypto.createCipheriv('aes-256-gcm', key.subarray(0, 32), iv);
  const enc = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final(), cipher.getAuthTag()]);
  return iv.toString('base64') + '.' + enc.toString('base64');
}

function decrypt(packed: string): string {
  const [ivB64, dataB64] = packed.split('.');
  const iv = Buffer.from(ivB64, 'base64');
  const buf = Buffer.from(dataB64, 'base64');
  const tag = buf.subarray(buf.length - 16);
  const data = buf.subarray(0, buf.length - 16);
  const key = Buffer.from(config.masterKey, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key.subarray(0, 32), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
}

/** JWKS endpoint payload: publish ALL non-expired public keys (active + rotation grace). */
export async function publicJwks() {
  const { rows } = await pool.query(`SELECT kid, public_key_pem FROM jwks`);
  const keys = [];
  for (const r of rows) {
    const spki = await importSPKI(r.public_key_pem, 'RS256');
    const jwk = await exportJWK(spki);
    keys.push({ ...jwk, kid: r.kid, use: 'sig', alg: 'RS256' });
  }
  return { keys };
}

/** Sign an access/ID token. Algorithm restricted to RS256. */
export async function signToken(payload: Record<string, unknown>, ttlS: number, type: 'access' | 'id') {
  const key = (await loadSigningKey())!;
  return new SignJWT(payload)
    .setProtectedHeader({ alg: 'RS256', kid: key.kid, typ: type })
    .setIssuer(config.issuer)
    .setIssuedAt()
    .setExpirationTime(`${ttlS}s`)
    .sign(key.privateKey);
}

/** Resource-server style verification (used by /userinfo; reusable in admin/blog). */
export async function verifyAccessToken(token: string, audience?: string) {
  const key = (await loadSigningKey())!;
  const { payload } = await jwtVerify(token, key.publicKey, {
    algorithms: ['RS256'],
    issuer: config.issuer,
    ...(audience ? { audience } : {}),
  });
  return payload;
}

export const sha256 = (s: string) => crypto.createHash('sha256').update(s).digest('hex');
