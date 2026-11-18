import type { Db, Row } from './db/driver.js';

export interface UserRow { id: string; email: string; displayName: string; pwHash: string; publicKey: JsonWebKey | null }
export interface PeerOut { id: string; email: string; displayName: string; publicKey: JsonWebKey }
export interface SummaryOut { id: string; peer: PeerOut; unread: number; last: { fromMe: boolean; status: 'sent' | 'burned'; at: number } | null }
export interface MessageOut {
  id: string; chatId: string; fromMe: boolean; status: 'sent' | 'burned';
  ciphertext?: string; iv?: string; burnSeconds: number; createdAt: number;
}

const WEEK = 7 * 24 * 3600 * 1000;
const toUser = (r: Row): UserRow => ({
  id: r.id, email: r.email, displayName: r.display_name, pwHash: r.pw_hash,
  publicKey: r.public_key ? (JSON.parse(r.public_key) as JsonWebKey) : null,
});
const pair = (a: string, b: string): [string, string] => (a < b ? [a, b] : [b, a]);

/** Phase 2 data: accounts, sessions, chats and burn-after-reading messages (ciphertext only). */
export class AccountStore {
  constructor(public readonly db: Db) {}

  async createUser(u: { id: string; email: string; displayName: string; pwHash: string; now: number }): Promise<boolean> {
    try {
      await this.db.exec(
        `INSERT INTO users (id, email, display_name, pw_hash, created_at) VALUES (?, ?, ?, ?, ?)`,
        [u.id, u.email, u.displayName, u.pwHash, u.now],
      );
      return true;
    } catch (e) {
      if (/duplicate|unique/i.test((e as Error).message)) return false;
      throw e;
    }
  }
  async userByEmail(email: string): Promise<UserRow | null> {
    const [r] = await this.db.query(`SELECT * FROM users WHERE email = ?`, [email]);
    return r ? toUser(r) : null;
  }
  async userById(id: string): Promise<UserRow | null> {
    const [r] = await this.db.query(`SELECT * FROM users WHERE id = ?`, [id]);
    return r ? toUser(r) : null;
  }
  async setPublicKey(userId: string, jwk: JsonWebKey): Promise<void> {
    await this.db.exec(`UPDATE users SET public_key = ? WHERE id = ?`, [JSON.stringify(jwk), userId]);
  }

  async createSession(tokenHash: string, userId: string, now: number, ttlMs: number): Promise<void> {
    await this.db.exec(`INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`, [tokenHash, userId, now, now + ttlMs]);
  }
  async userForSession(tokenHash: string, now: number): Promise<UserRow | null> {
    const [s] = await this.db.query(`SELECT user_id, expires_at FROM sessions WHERE token_hash = ?`, [tokenHash]);
    if (!s || Number(s.expires_at) <= now) return null;
    return this.userById(s.user_id);
  }
  async deleteSession(tokenHash: string): Promise<void> {
    await this.db.exec(`DELETE FROM sessions WHERE token_hash = ?`, [tokenHash]);
  }
  sweepSessions(now: number): Promise<number> {
    return this.db.exec(`DELETE FROM sessions WHERE expires_at <= ?`, [now]);
  }

  /** Unread messages that nobody opened for a week are burned. */
  expireMessages(now: number): Promise<number> {
    return this.db.exec(
      `UPDATE messages SET status = 'burned', ciphertext = NULL, iv = NULL WHERE status = 'sent' AND created_at < ?`,
      [now - WEEK],
    );
  }

  async openChat(me: string, peer: string, id: string, now: number): Promise<string> {
    const [a, b] = pair(me, peer);
    return this.db.transaction(async (tx) => {
      const [c] = await tx.query(`SELECT id FROM chats WHERE user_a = ? AND user_b = ? FOR UPDATE`, [a, b]);
      if (c) return c.id as string;
      await tx.exec(`INSERT INTO chats (id, user_a, user_b, created_at) VALUES (?, ?, ?, ?)`, [id, a, b, now]);
      return id;
    });
  }

  private async summary(chat: Row, me: string): Promise<SummaryOut> {
    const peerId = chat.user_a === me ? chat.user_b : chat.user_a;
    const [p] = await this.db.query(`SELECT id, email, display_name, public_key FROM users WHERE id = ?`, [peerId]);
    const [u] = await this.db.query(`SELECT COUNT(*) AS c FROM messages WHERE chat_id = ? AND sender_id <> ? AND status = 'sent'`, [chat.id, me]);
    const [l] = await this.db.query(`SELECT sender_id, status, created_at FROM messages WHERE chat_id = ? ORDER BY created_at DESC, id DESC LIMIT 1`, [chat.id]);
    return {
      id: chat.id,
      peer: { id: p.id, email: p.email, displayName: p.display_name, publicKey: JSON.parse(p.public_key) as JsonWebKey },
      unread: Number(u.c),
      last: l ? { fromMe: l.sender_id === me, status: l.status, at: Number(l.created_at) } : null,
    };
  }
  async chatsFor(me: string): Promise<SummaryOut[]> {
    const rows = await this.db.query(`SELECT id, user_a, user_b FROM chats WHERE user_a = ? OR user_b = ?`, [me, me]);
    return Promise.all(rows.map((c) => this.summary(c, me)));
  }
  async chatFor(me: string, chatId: string): Promise<SummaryOut | null> {
    const [c] = await this.db.query(`SELECT id, user_a, user_b FROM chats WHERE id = ? AND (user_a = ? OR user_b = ?)`, [chatId, me, me]);
    return c ? this.summary(c, me) : null;
  }
  async peerOf(me: string, chatId: string): Promise<string | null> {
    const [c] = await this.db.query(`SELECT user_a, user_b FROM chats WHERE id = ? AND (user_a = ? OR user_b = ?)`, [chatId, me, me]);
    return c ? (c.user_a === me ? c.user_b : c.user_a) : null;
  }

  async messages(me: string, chatId: string): Promise<MessageOut[]> {
    const rows = await this.db.query(
      `SELECT id, sender_id, status, ciphertext, iv, burn_seconds, created_at FROM messages WHERE chat_id = ? ORDER BY created_at ASC, id ASC`, [chatId],
    );
    return rows.map((m) => ({
      id: m.id, chatId, fromMe: m.sender_id === me, status: m.status,
      ...(m.status === 'sent' && m.ciphertext ? { ciphertext: Buffer.from(m.ciphertext).toString('base64'), iv: Buffer.from(m.iv).toString('base64') } : {}),
      burnSeconds: Number(m.burn_seconds), createdAt: Number(m.created_at),
    }));
  }
  async addMessage(m: { id: string; chatId: string; senderId: string; ciphertext: Buffer; iv: Buffer; burnSeconds: number; now: number }): Promise<MessageOut> {
    await this.db.exec(
      `INSERT INTO messages (id, chat_id, sender_id, ciphertext, iv, burn_seconds, status, created_at) VALUES (?, ?, ?, ?, ?, ?, 'sent', ?)`,
      [m.id, m.chatId, m.senderId, m.ciphertext, m.iv, m.burnSeconds, m.now],
    );
    return { id: m.id, chatId: m.chatId, fromMe: true, status: 'sent', ciphertext: m.ciphertext.toString('base64'), iv: m.iv.toString('base64'), burnSeconds: m.burnSeconds, createdAt: m.now };
  }

  /** Read and destroy in one locked transaction. Only the recipient can do it, and only once. */
  reveal(me: string, messageId: string): Promise<{ ciphertext: Buffer; iv: Buffer; chatId: string; peerId: string } | null> {
    return this.db.transaction(async (tx) => {
      const [m] = await tx.query(`SELECT chat_id, sender_id, status, ciphertext, iv FROM messages WHERE id = ? FOR UPDATE`, [messageId]);
      if (!m || m.sender_id === me || m.status !== 'sent' || !m.ciphertext) return null;
      const [c] = await tx.query(`SELECT user_a, user_b FROM chats WHERE id = ? AND (user_a = ? OR user_b = ?)`, [m.chat_id, me, me]);
      if (!c) return null;
      await tx.exec(`UPDATE messages SET status = 'burned', ciphertext = NULL, iv = NULL WHERE id = ?`, [messageId]);
      return { ciphertext: Buffer.from(m.ciphertext), iv: Buffer.from(m.iv), chatId: m.chat_id, peerId: c.user_a === me ? c.user_b : c.user_a };
    });
  }

  /** Right to erasure: removes the account, its sessions, chats and messages. Returns the people who need a refresh. */
  deleteUser(userId: string): Promise<string[]> {
    return this.db.transaction(async (tx) => {
      const chats = await tx.query(`SELECT id, user_a, user_b FROM chats WHERE user_a = ? OR user_b = ?`, [userId, userId]);
      for (const c of chats) {
        await tx.exec(`DELETE FROM messages WHERE chat_id = ?`, [c.id]);
        await tx.exec(`DELETE FROM chats WHERE id = ?`, [c.id]);
      }
      await tx.exec(`DELETE FROM sessions WHERE user_id = ?`, [userId]);
      await tx.exec(`DELETE FROM users WHERE id = ?`, [userId]);
      return chats.map((c) => (c.user_a === userId ? c.user_b : c.user_a) as string);
    });
  }
}
