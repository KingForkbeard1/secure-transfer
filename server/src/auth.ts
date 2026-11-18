import { createHash, randomBytes, scrypt as scryptCb, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCb) as (pw: string, salt: Buffer, len: number, o: { N: number; r: number; p: number; maxmem: number }) => Promise<Buffer>;

export const SCRYPT_N = 2 ** 15; // about 100 ms; tests use a lower cost
const opts = (N: number) => ({ N, r: 8, p: 1, maxmem: 128 * 1024 * 1024 });

/** Stored as scrypt$N$salt$hash so the cost can be raised later without breaking old accounts. */
export async function hashPassword(pw: string, N = SCRYPT_N): Promise<string> {
  const salt = randomBytes(16);
  const h = await scrypt(pw.normalize('NFKC'), salt, 64, opts(N));
  return `scrypt$${N}$${salt.toString('hex')}$${h.toString('hex')}`;
}
const DUMMY = `scrypt$${SCRYPT_N}$${'00'.repeat(16)}$${'00'.repeat(64)}`;

export async function verifyPassword(pw: string, stored: string | null): Promise<boolean> {
  const [alg, n, salt, hash] = (stored ?? DUMMY).split('$');
  if (alg !== 'scrypt') return false;
  const h = await scrypt(pw.normalize('NFKC'), Buffer.from(salt, 'hex'), 64, opts(Number(n)));
  const ok = timingSafeEqual(h, Buffer.from(hash, 'hex'));
  return ok && stored !== null; // unknown users cost the same time as wrong passwords
}

export const newSessionToken = () => randomBytes(32).toString('base64url');
export const hashToken = (t: string) => createHash('sha256').update(t).digest('hex');
