import { createHash, timingSafeEqual } from 'node:crypto';
import type { Db } from './db/driver.js';

export type Kind = 'text' | 'file';
export const MAX_ATTEMPTS = 5;
export const TOMBSTONE_TTL_MS = 7 * 24 * 3600 * 1000;

export interface NewSecret {
  id: string;
  ciphertext: Buffer;
  iv: Buffer;
  kind: Kind;
  salt: string | null;
  verifier: string | null; // raw verifier from the client; only its hash is stored
  now: number;
  ttlSeconds: number;
}
export interface SecretMeta { kind: Kind; passphraseRequired: boolean; salt: string | null }
export type RevealResult =
  | { ok: true; ciphertext: Buffer; iv: Buffer; kind: Kind }
  | { ok: false; reason: 'gone' }
  | { ok: false; reason: 'bad-verifier'; attemptsLeft: number };
export type Status = 'waiting' | 'opened' | 'expired';

const sha256hex = (s: string) => createHash('sha256').update(s).digest('hex');
function safeEqualHex(a: string, b: string): boolean {
  const x = Buffer.from(a, 'hex');
  const y = Buffer.from(b, 'hex');
  return x.length === y.length && x.length > 0 && timingSafeEqual(x, y);
}

/** Phase 1 data: one-time secrets. Works on MySQL and SQLite through the Db interface. */
export class SecretStore {
  constructor(public readonly db: Db) {}

  async create(s: NewSecret): Promise<number> {
    const expiresAt = s.now + s.ttlSeconds * 1000;
    await this.db.exec(
      `INSERT INTO secrets (id, ciphertext, iv, kind, salt, verifier_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [s.id, s.ciphertext, s.iv, s.kind, s.salt, s.verifier ? sha256hex(s.verifier) : null, s.now, expiresAt],
    );
    return expiresAt;
  }

  /** Read-only. Never burns the secret. */
  async meta(id: string, now: number): Promise<SecretMeta | null> {
    const [r] = await this.db.query(`SELECT kind, salt, verifier_hash, expires_at FROM secrets WHERE id = ?`, [id]);
    if (!r || Number(r.expires_at) <= now) return null;
    return { kind: r.kind, passphraseRequired: !!r.verifier_hash, salt: r.salt ?? null };
  }

  /** Verify, then read and delete inside one transaction. The row is locked, so two requests can never both succeed. */
  reveal(id: string, verifier: string | null, now: number): Promise<RevealResult> {
    return this.db.transaction(async (tx): Promise<RevealResult> => {
      const [row] = await tx.query(
        `SELECT kind, verifier_hash, attempts, expires_at FROM secrets WHERE id = ? FOR UPDATE`, [id],
      );
      if (!row) return { ok: false, reason: 'gone' };
      const burn = async (status: 'opened' | 'expired') => {
        await tx.exec(`DELETE FROM secrets WHERE id = ?`, [id]);
        await tx.exec(`DELETE FROM tombstones WHERE id = ?`, [id]);
        await tx.exec(`INSERT INTO tombstones (id, status, at) VALUES (?, ?, ?)`, [id, status, now]);
      };
      if (Number(row.expires_at) <= now) { await burn('expired'); return { ok: false, reason: 'gone' }; }
      if (row.verifier_hash) {
        const given = verifier ? sha256hex(verifier) : '';
        if (!safeEqualHex(row.verifier_hash, given)) {
          const attempts = Number(row.attempts) + 1;
          if (attempts >= MAX_ATTEMPTS) { await burn('expired'); return { ok: false, reason: 'bad-verifier', attemptsLeft: 0 }; }
          await tx.exec(`UPDATE secrets SET attempts = ? WHERE id = ?`, [attempts, id]);
          return { ok: false, reason: 'bad-verifier', attemptsLeft: MAX_ATTEMPTS - attempts };
        }
      }
      const [data] = await tx.query(`SELECT ciphertext, iv FROM secrets WHERE id = ?`, [id]);
      await burn('opened');
      return { ok: true, ciphertext: Buffer.from(data.ciphertext), iv: Buffer.from(data.iv), kind: row.kind };
    });
  }

  async status(id: string, now: number): Promise<Status | null> {
    const [row] = await this.db.query(`SELECT expires_at FROM secrets WHERE id = ?`, [id]);
    if (row) return Number(row.expires_at) <= now ? 'expired' : 'waiting';
    const [t] = await this.db.query(`SELECT status FROM tombstones WHERE id = ?`, [id]);
    return t ? (t.status as Status) : null;
  }

  /** Destroys unopened secrets past their expiry and leaves a content-free tombstone. */
  sweep(now: number): Promise<number> {
    return this.db.transaction(async (tx) => {
      const ids = await tx.query(`SELECT id FROM secrets WHERE expires_at <= ? FOR UPDATE`, [now]);
      for (const { id } of ids) {
        await tx.exec(`DELETE FROM secrets WHERE id = ?`, [id]);
        await tx.exec(`DELETE FROM tombstones WHERE id = ?`, [id]);
        await tx.exec(`INSERT INTO tombstones (id, status, at) VALUES (?, 'expired', ?)`, [id, now]);
      }
      await tx.exec(`DELETE FROM tombstones WHERE at <= ?`, [now - TOMBSTONE_TTL_MS]);
      return ids.length;
    });
  }
}
