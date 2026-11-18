import { Router, type NextFunction, type Request, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import type { AccountStore, UserRow } from './accounts.js';
import { hashPassword, hashToken, newSessionToken, SCRYPT_N, verifyPassword } from './auth.js';
import type { EventHub } from './events.js';

const COOKIE = 'st_session';
const SESSION_MS = 30 * 24 * 3600 * 1000;
const MAX_MESSAGE_BYTES = 64 * 1024;
const B64 = /^[A-Za-z0-9+/]+={0,2}$/;
const UUID = /^[0-9a-fA-F-]{36}$/;

const email = z.string().trim().toLowerCase().max(254).regex(/^[^\s@]+@[^\s@]+\.[^\s@]+$/);
const password = z.string().min(8).max(200);
const registerBody = z.object({ email, password, displayName: z.string().trim().min(1).max(40) });
const loginBody = z.object({ email, password });
const keyBody = z.object({
  jwk: z.strictObject({ kty: z.literal('EC'), crv: z.literal('P-256'), x: z.string().regex(/^[A-Za-z0-9_-]{43}$/), y: z.string().regex(/^[A-Za-z0-9_-]{43}$/) }),
});
const sendBody = z.object({
  ciphertext: z.string().min(24).max(Math.ceil((MAX_MESSAGE_BYTES * 4) / 3) + 8).regex(B64),
  iv: z.string().length(16).regex(B64),
  burnSeconds: z.union([z.literal(15), z.literal(30), z.literal(60)]),
});

export interface ChatRouteOptions {
  accounts: AccountStore;
  hub: EventHub;
  now: () => number;
  secureCookie: boolean;
  scryptN?: number;
  limits: { auth: number; lookup: number; send: number };
}

const cookieOf = (req: Request): string | undefined =>
  (req.headers.cookie ?? '').split(';').map((s) => s.trim()).find((s) => s.startsWith(`${COOKIE}=`))?.slice(COOKIE.length + 1);

export function chatRouter(o: ChatRouteOptions): Router {
  const { accounts, hub, now } = o;
  const r = Router();
  const mk = (max: number, windowMs: number) =>
    rateLimit({ windowMs, limit: max, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'rate-limited' } });
  const authLimit = mk(o.limits.auth, 15 * 60_000);
  const lookupLimit = mk(o.limits.lookup, 5 * 60_000);
  const sendLimit = mk(o.limits.send, 10 * 60_000);
  const cookieOpts = { httpOnly: true, sameSite: 'strict' as const, secure: o.secureCookie, path: '/' };

  // Cookie sessions need CSRF protection: SameSite=Strict plus a same-origin check on every state-changing request.
  const sameOrigin = (req: Request, res: Response, next: NextFunction) => {
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return next();
    const origin = req.headers.origin;
    if (origin) {
      try { if (new URL(origin).host !== req.headers.host) return res.status(403).json({ error: 'forbidden' }); }
      catch { return res.status(403).json({ error: 'forbidden' }); }
    }
    next();
  };
  const requireUser = async (req: Request, res: Response, next: NextFunction) => {
    const t = cookieOf(req);
    const u = t ? await accounts.userForSession(hashToken(t), now()) : null;
    if (!u) return res.status(401).json({ error: 'not-signed-in' });
    res.locals.user = u;
    next();
  };
  const me = (res: Response) => res.locals.user as UserRow;
  const publicUser = (u: UserRow) => ({ id: u.id, email: u.email, displayName: u.displayName, publicKey: u.publicKey });
  const startSession = async (res: Response, userId: string) => {
    const token = newSessionToken();
    await accounts.createSession(hashToken(token), userId, now(), SESSION_MS);
    res.cookie(COOKIE, token, { ...cookieOpts, maxAge: SESSION_MS });
  };
  const validId = (req: Request, res: Response, next: NextFunction) =>
    UUID.test(String(req.params.id)) ? next() : res.status(404).json({ error: 'not-found' });

  r.use(['/auth', '/me', '/users', '/chats', '/messages', '/events'], sameOrigin);

  r.post('/auth/register', authLimit, async (req, res) => {
    const b = registerBody.safeParse(req.body);
    if (!b.success) return res.status(400).json({ error: 'invalid' });
    const id = randomUUID();
    const ok = await accounts.createUser({ id, email: b.data.email, displayName: b.data.displayName, pwHash: await hashPassword(b.data.password, o.scryptN ?? SCRYPT_N), now: now() });
    if (!ok) return res.status(409).json({ error: 'email-taken' });
    await startSession(res, id);
    res.status(201).json({ id, email: b.data.email, displayName: b.data.displayName, publicKey: null });
  });
  r.post('/auth/login', authLimit, async (req, res) => {
    const b = loginBody.safeParse(req.body);
    if (!b.success) return res.status(401).json({ error: 'bad-credentials' });
    const u = await accounts.userByEmail(b.data.email);
    const ok = await verifyPassword(b.data.password, u?.pwHash ?? null);
    if (!ok || !u) return res.status(401).json({ error: 'bad-credentials' });
    await startSession(res, u.id);
    res.json(publicUser(u));
  });
  r.post('/auth/logout', async (req, res) => {
    const t = cookieOf(req);
    if (t) await accounts.deleteSession(hashToken(t));
    res.clearCookie(COOKIE, cookieOpts);
    res.status(204).end();
  });

  r.get('/me', requireUser, (_req, res) => res.json(publicUser(me(res))));
  r.put('/me/key', requireUser, async (req, res) => {
    const b = keyBody.safeParse(req.body);
    if (!b.success) return res.status(400).json({ error: 'invalid' });
    await accounts.setPublicKey(me(res).id, b.data.jwk);
    res.status(204).end();
  });
  r.delete('/me', requireUser, authLimit, async (req, res) => {
    const pw = z.object({ password: z.string().max(200) }).safeParse(req.body);
    if (!pw.success || !(await verifyPassword(pw.data.password, me(res).pwHash))) return res.status(401).json({ error: 'bad-credentials' });
    const peers = await accounts.deleteUser(me(res).id);
    hub.notify(peers);
    res.clearCookie(COOKIE, cookieOpts);
    res.status(204).end();
  });

  // Exact email only: there is deliberately no way to browse or list users.
  r.get('/users/lookup', requireUser, lookupLimit, async (req, res) => {
    const e = email.safeParse(req.query.email);
    if (!e.success) return res.status(404).json({ error: 'not-found' });
    const u = await accounts.userByEmail(e.data);
    if (!u || u.id === me(res).id || !u.publicKey) return res.status(404).json({ error: 'not-found' });
    res.json({ id: u.id, email: u.email, displayName: u.displayName, publicKey: u.publicKey });
  });

  r.post('/chats', requireUser, async (req, res) => {
    const b = z.object({ peerId: z.string().regex(UUID) }).safeParse(req.body);
    if (!b.success) return res.status(400).json({ error: 'invalid' });
    if (b.data.peerId === me(res).id) return res.status(400).json({ error: 'self-chat' });
    const peer = await accounts.userById(b.data.peerId);
    if (!peer || !peer.publicKey || !me(res).publicKey) return res.status(404).json({ error: 'not-found' });
    const id = await accounts.openChat(me(res).id, peer.id, randomUUID(), now());
    res.json(await accounts.chatFor(me(res).id, id));
  });
  r.get('/chats', requireUser, async (_req, res) => res.json(await accounts.chatsFor(me(res).id)));
  r.get('/chats/:id', requireUser, validId, async (req, res) => {
    const c = await accounts.chatFor(me(res).id, String(req.params.id));
    return c ? res.json(c) : res.status(404).json({ error: 'not-found' });
  });
  r.get('/chats/:id/messages', requireUser, validId, async (req, res) => {
    const id = String(req.params.id);
    if (!(await accounts.peerOf(me(res).id, id))) return res.status(404).json({ error: 'not-found' });
    res.json(await accounts.messages(me(res).id, id));
  });
  r.post('/chats/:id/messages', requireUser, validId, sendLimit, async (req, res) => {
    const id = String(req.params.id);
    const peer = await accounts.peerOf(me(res).id, id);
    if (!peer) return res.status(404).json({ error: 'not-found' });
    const b = sendBody.safeParse(req.body);
    if (!b.success) return res.status(400).json({ error: 'invalid' });
    const ciphertext = Buffer.from(b.data.ciphertext, 'base64');
    const iv = Buffer.from(b.data.iv, 'base64');
    if (iv.length !== 12 || ciphertext.length < 17 || ciphertext.length > MAX_MESSAGE_BYTES) return res.status(400).json({ error: 'invalid' });
    const m = await accounts.addMessage({ id: randomUUID(), chatId: id, senderId: me(res).id, ciphertext, iv, burnSeconds: b.data.burnSeconds, now: now() });
    hub.notify([me(res).id, peer]);
    res.status(201).json(m);
  });
  r.post('/messages/:id/reveal', requireUser, validId, async (req, res) => {
    const out = await accounts.reveal(me(res).id, String(req.params.id));
    if (!out) return res.status(404).json({ error: 'gone' });
    hub.notify([me(res).id, out.peerId]);
    res.json({ ciphertext: out.ciphertext.toString('base64'), iv: out.iv.toString('base64') });
  });

  r.get('/events', requireUser, (_req, res) => hub.add(me(res).id, res));
  return r;
}
