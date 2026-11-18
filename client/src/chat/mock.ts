import { b64e, b64d } from '../crypto';
import { ChatError, type ChatService, type ChatSummary, type Message, type Peer, type User } from './types';

/**
 * Browser-only stand-in for the Phase 2 backend. It behaves like the real server will:
 * it stores only ciphertext and public keys, deletes ciphertext atomically on reveal,
 * and expires unread messages after 7 days. Open two tabs and sign in as two different
 * people to chat with yourself.
 */
const DB = 'st.mock.db';
const SESSION = 'st.mock.session';
const WEEK = 7 * 24 * 3600 * 1000;

interface UserRec { id: string; email: string; displayName: string; salt: string; hash: string; publicKey: JsonWebKey | null }
interface ChatRec { id: string; a: string; b: string }
interface MsgRec { id: string; chatId: string; senderId: string; ciphertext: string | null; iv: string | null; burnSeconds: number; status: 'sent' | 'burned'; createdAt: number }
interface Db { users: UserRec[]; chats: ChatRec[]; messages: MsgRec[] }

export interface MockOptions { storage?: Storage; session?: Storage; now?: () => number; iterations?: number }

const enc = new TextEncoder();
async function hashPw(pw: string, salt: Uint8Array, iterations: number) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return b64e(new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, k, 256)));
}

export function createMockChatService(opts: MockOptions = {}): ChatService {
  const store = opts.storage ?? localStorage;
  const session = opts.session ?? sessionStorage;
  const now = opts.now ?? Date.now;
  const iterations = opts.iterations ?? 200_000;
  const bus = new EventTarget();
  if (typeof window !== 'undefined') {
    window.addEventListener('storage', (e) => { if (e.key === DB) bus.dispatchEvent(new Event('change')); });
  }

  const load = (): Db => {
    try { const v = store.getItem(DB); if (v) return JSON.parse(v) as Db; } catch { /* corrupt: start clean */ }
    return { users: [], chats: [], messages: [] };
  };
  const save = (d: Db) => { store.setItem(DB, JSON.stringify(d)); bus.dispatchEvent(new Event('change')); };
  const sweep = (d: Db) => {
    let changed = false;
    for (const m of d.messages) {
      if (m.status === 'sent' && now() - m.createdAt > WEEK) { m.status = 'burned'; m.ciphertext = m.iv = null; changed = true; }
    }
    if (changed) save(d);
  };
  const toUser = (u: UserRec): User => ({ id: u.id, email: u.email, displayName: u.displayName, publicKey: u.publicKey });
  const meId = () => session.getItem(SESSION);
  const needMe = (d: Db): UserRec => {
    const u = d.users.find((x) => x.id === meId());
    if (!u) throw new ChatError('not-signed-in');
    return u;
  };
  const summary = (d: Db, c: ChatRec, me: UserRec): ChatSummary => {
    const peerRec = d.users.find((u) => u.id === (c.a === me.id ? c.b : c.a))!;
    const msgs = d.messages.filter((m) => m.chatId === c.id);
    const last = msgs[msgs.length - 1];
    return {
      id: c.id,
      peer: { id: peerRec.id, email: peerRec.email, displayName: peerRec.displayName, publicKey: peerRec.publicKey as JsonWebKey },
      unread: msgs.filter((m) => m.senderId !== me.id && m.status === 'sent').length,
      last: last ? { fromMe: last.senderId === me.id, status: last.status, at: last.createdAt } : null,
    };
  };
  const toMsg = (m: MsgRec, me: UserRec): Message => ({
    id: m.id, chatId: m.chatId, fromMe: m.senderId === me.id, status: m.status,
    ...(m.status === 'sent' ? { ciphertext: m.ciphertext!, iv: m.iv! } : {}),
    burnSeconds: m.burnSeconds, createdAt: m.createdAt,
  });
  const member = (d: Db, chatId: string, me: UserRec) => {
    const c = d.chats.find((x) => x.id === chatId && (x.a === me.id || x.b === me.id));
    if (!c) throw new ChatError('not-found');
    return c;
  };

  return {
    async me() { const u = load().users.find((x) => x.id === meId()); return u ? toUser(u) : null; },
    async register(email, password, displayName) {
      const e = email.trim().toLowerCase();
      if (!/^\S+@\S+\.\S+$/.test(e) || password.length < 8 || !displayName.trim()) throw new ChatError('invalid');
      const d = load();
      if (d.users.some((u) => u.email === e)) throw new ChatError('email-taken');
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const rec: UserRec = { id: crypto.randomUUID(), email: e, displayName: displayName.trim().slice(0, 40), salt: b64e(salt), hash: await hashPw(password, salt, iterations), publicKey: null };
      d.users.push(rec); session.setItem(SESSION, rec.id); save(d); // session first, so listeners see the signed-in user
      return toUser(rec);
    },
    async login(email, password) {
      const d = load();
      const u = d.users.find((x) => x.email === email.trim().toLowerCase());
      // always do the hashing work so a wrong email and a wrong password look the same
      const salt = u ? b64d(u.salt) : new Uint8Array(16);
      const h = await hashPw(password, salt, iterations);
      if (!u || u.hash !== h) throw new ChatError('bad-credentials');
      session.setItem(SESSION, u.id); bus.dispatchEvent(new Event('change'));
      return toUser(u);
    },
    async logout() { session.removeItem(SESSION); bus.dispatchEvent(new Event('change')); },
    async setPublicKey(jwk) { const d = load(); needMe(d).publicKey = jwk; save(d); },
    async lookup(email) {
      const d = load(); const me = needMe(d);
      const u = d.users.find((x) => x.email === email.trim().toLowerCase());
      if (!u || u.id === me.id || !u.publicKey) return null;
      return { id: u.id, email: u.email, displayName: u.displayName, publicKey: u.publicKey } satisfies Peer;
    },
    async openChat(peerId) {
      const d = load(); const me = needMe(d);
      if (peerId === me.id) throw new ChatError('self-chat');
      const peer = d.users.find((u) => u.id === peerId);
      if (!peer || !peer.publicKey) throw new ChatError('not-found');
      let c = d.chats.find((x) => (x.a === me.id && x.b === peerId) || (x.a === peerId && x.b === me.id));
      if (!c) { c = { id: crypto.randomUUID(), a: me.id, b: peerId }; d.chats.push(c); save(d); }
      return summary(d, c, me);
    },
    async listChats() {
      const d = load(); const me = needMe(d); sweep(d);
      return d.chats.filter((c) => c.a === me.id || c.b === me.id).map((c) => summary(d, c, me));
    },
    async getChat(chatId) { const d = load(); const me = needMe(d); return summary(d, member(d, chatId, me), me); },
    async messages(chatId) {
      const d = load(); const me = needMe(d); member(d, chatId, me); sweep(d);
      return d.messages.filter((m) => m.chatId === chatId).map((m) => toMsg(m, me));
    },
    async send(chatId, ciphertext, iv, burnSeconds) {
      const d = load(); const me = needMe(d); member(d, chatId, me);
      if (!ciphertext || !iv || ![15, 30, 60].includes(burnSeconds)) throw new ChatError('invalid');
      const m: MsgRec = { id: crypto.randomUUID(), chatId, senderId: me.id, ciphertext, iv, burnSeconds, status: 'sent', createdAt: now() };
      d.messages.push(m); save(d);
      return toMsg(m, me);
    },
    async reveal(messageId) {
      const d = load(); const me = needMe(d);
      const m = d.messages.find((x) => x.id === messageId);
      if (!m || m.senderId === me.id || m.status !== 'sent') return null;
      const c = d.chats.find((x) => x.id === m.chatId);
      if (!c || (c.a !== me.id && c.b !== me.id)) return null;
      const out = { ciphertext: m.ciphertext!, iv: m.iv! };
      m.status = 'burned'; m.ciphertext = m.iv = null; save(d); // read and destroy in one step
      return out;
    },
    async deleteAccount(password) {
      const d = load(); const u = needMe(d);
      if ((await hashPw(password, b64d(u.salt), iterations)) !== u.hash) throw new ChatError('bad-credentials');
      const mine = d.chats.filter((c) => c.a === u.id || c.b === u.id).map((c) => c.id);
      d.messages = d.messages.filter((m) => !mine.includes(m.chatId));
      d.chats = d.chats.filter((c) => !mine.includes(c.id));
      d.users = d.users.filter((x) => x.id !== u.id);
      session.removeItem(SESSION); save(d);
    },
    subscribe(listener) {
      bus.addEventListener('change', listener);
      return () => bus.removeEventListener('change', listener);
    },
  };
}
