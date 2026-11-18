import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import request from 'supertest';
import type { AddressInfo } from 'node:net';
import { createApp } from '../src/app';
import { EventHub } from '../src/events';
import { KINDS, LIMITS, makeStores, type Stores } from './helpers';

const X = 'A'.repeat(43);
const Y = 'B'.repeat(43);
const jwk = (n = X) => ({ kty: 'EC', crv: 'P-256', x: n, y: Y });
const ct = (n = 64) => Buffer.alloc(n, 5).toString('base64');
const iv = Buffer.alloc(12, 2).toString('base64');

for (const kind of KINDS) describe(`Phase 2 API on ${kind}`, () => {
  let s: Stores;
  let hub: EventHub;
  let app: ReturnType<typeof createApp>;
  let clock: number;
  const build = (limits = {}) =>
    createApp({ secrets: s.secrets, accounts: s.accounts, hub, now: () => clock, scryptN: 1024, limits: { ...LIMITS, ...limits } });

  beforeEach(async () => {
    s = await makeStores(kind);
    hub = new EventHub();
    clock = 1_700_000_000_000;
    app = build();
  });
  afterEach(async () => { hub.closeAll(); await s.db.close(); });

  async function person(email: string, name: string, key = X) {
    const agent = request.agent(app);
    const r = await agent.post('/api/auth/register').send({ email, password: 'longpassword', displayName: name });
    expect(r.status).toBe(201);
    expect((await agent.put('/api/me/key').send({ jwk: jwk(key) })).status).toBe(204);
    return { agent, id: r.body.id as string, cookie: String(r.headers['set-cookie'][0]).split(';')[0] };
  }

  describe('accounts and sessions', () => {
    it('registers, sets a hardened session cookie, and never stores the password', async () => {
      const r = await request(app).post('/api/auth/register').send({ email: ' Amina@Example.com ', password: 'longpassword', displayName: 'Amina' });
      expect(r.status).toBe(201);
      expect(r.body).toMatchObject({ email: 'amina@example.com', displayName: 'Amina', publicKey: null });
      const cookie = String(r.headers['set-cookie'][0]);
      expect(cookie).toMatch(/HttpOnly/i);
      expect(cookie).toMatch(/SameSite=Strict/i);
      const [row] = await s.db.query('SELECT pw_hash FROM users');
      expect(row.pw_hash).toMatch(/^scrypt\$/);
      expect(row.pw_hash).not.toContain('longpassword');
      const sess = await s.db.query('SELECT token_hash FROM sessions');
      expect(sess[0].token_hash).toHaveLength(64); // only a hash of the token is stored
      expect(cookie).not.toContain(sess[0].token_hash);
    });
    it('rejects duplicates and weak input', async () => {
      await person('a@example.com', 'A');
      expect((await request(app).post('/api/auth/register').send({ email: 'A@example.com', password: 'longpassword', displayName: 'X' })).status).toBe(409);
      for (const b of [{ email: 'bad', password: 'longpassword', displayName: 'X' }, { email: 'b@example.com', password: 'short', displayName: 'X' }, { email: 'b@example.com', password: 'longpassword', displayName: '' }]) {
        expect((await request(app).post('/api/auth/register').send(b)).status).toBe(400);
      }
    });
    it('logs in only with the right password and gives the same error for unknown emails', async () => {
      await person('a@example.com', 'A');
      const bad = await request(app).post('/api/auth/login').send({ email: 'a@example.com', password: 'wrongpassword' });
      const none = await request(app).post('/api/auth/login').send({ email: 'nobody@example.com', password: 'longpassword' });
      expect([bad.status, none.status]).toEqual([401, 401]);
      expect(bad.body).toEqual(none.body);
      const agent = request.agent(app);
      expect((await agent.post('/api/auth/login').send({ email: 'a@example.com', password: 'longpassword' })).status).toBe(200);
      expect((await agent.get('/api/me')).body.email).toBe('a@example.com');
      expect((await agent.post('/api/auth/logout')).status).toBe(204);
      expect((await agent.get('/api/me')).status).toBe(401);
    });
    it('sessions expire after 30 days and unauthenticated calls are refused', async () => {
      const a = await person('a@example.com', 'A');
      expect((await request(app).get('/api/chats')).status).toBe(401);
      clock += 31 * 24 * 3600 * 1000;
      expect((await a.agent.get('/api/me')).status).toBe(401);
    });
    it('blocks cross-site state-changing requests (CSRF)', async () => {
      const a = await person('a@example.com', 'A');
      const r = await a.agent.put('/api/me/key').set('Origin', 'https://evil.example').send({ jwk: jwk() });
      expect(r.status).toBe(403);
      expect((await a.agent.put('/api/me/key').set('Origin', 'http://127.0.0.1').set('Host', '127.0.0.1').send({ jwk: jwk() })).status).toBe(204);
    });
    it('rate-limits login attempts', async () => {
      const limited = request(build({ auth: 3 }));
      for (let i = 0; i < 3; i++) await limited.post('/api/auth/login').send({ email: 'x@example.com', password: 'longpassword' });
      expect((await limited.post('/api/auth/login').send({ email: 'x@example.com', password: 'longpassword' })).status).toBe(429);
    });
    it('only accepts P-256 public keys with no private part', async () => {
      const a = await person('a@example.com', 'A');
      for (const bad of [{ ...jwk(), d: 'secret' }, { ...jwk(), crv: 'P-384' }, { ...jwk(), x: 'short' }]) {
        expect((await a.agent.put('/api/me/key').send({ jwk: bad })).status).toBe(400);
      }
    });
  });

  describe('search and chats', () => {
    it('finds people only by exact email, and only if they have a key', async () => {
      const a = await person('a@example.com', 'Amina');
      await person('b@example.com', 'Brian', 'C'.repeat(43));
      await request(app).post('/api/auth/register').send({ email: 'nokey@example.com', password: 'longpassword', displayName: 'No Key' });
      const hit = await a.agent.get('/api/users/lookup').query({ email: 'B@example.com' });
      expect(hit.status).toBe(200);
      expect(hit.body).toMatchObject({ displayName: 'Brian', email: 'b@example.com' });
      expect(hit.body.pwHash).toBeUndefined();
      expect((await a.agent.get('/api/users/lookup').query({ email: 'b@exam' })).status).toBe(404); // no partial matches
      expect((await a.agent.get('/api/users/lookup').query({ email: 'nokey@example.com' })).status).toBe(404);
      expect((await a.agent.get('/api/users/lookup').query({ email: 'a@example.com' })).status).toBe(404); // not yourself
      expect((await request(app).get('/api/users/lookup').query({ email: 'b@example.com' })).status).toBe(401);
    });
    it('opens one chat per pair, whoever starts it', async () => {
      const a = await person('a@example.com', 'A');
      const b = await person('b@example.com', 'B', 'C'.repeat(43));
      const c1 = (await a.agent.post('/api/chats').send({ peerId: b.id })).body;
      const c2 = (await b.agent.post('/api/chats').send({ peerId: a.id })).body;
      expect(c2.id).toBe(c1.id);
      expect(c1.peer.displayName).toBe('B');
      expect((await a.agent.post('/api/chats').send({ peerId: a.id })).status).toBe(400);
      expect((await a.agent.post('/api/chats').send({ peerId: '00000000-0000-0000-0000-000000000000' })).status).toBe(404);
      expect((await a.agent.get('/api/chats')).body).toHaveLength(1);
    });
  });

  describe('burn-after-reading messages', () => {
    async function setup() {
      const a = await person('a@example.com', 'Amina');
      const b = await person('b@example.com', 'Brian', 'C'.repeat(43));
      const chat = (await a.agent.post('/api/chats').send({ peerId: b.id })).body;
      return { a, b, chat };
    }
    it('delivers ciphertext once: recipient reveals, then it is burned for both and gone from the database', async () => {
      const { a, b, chat } = await setup();
      const sent = await a.agent.post(`/api/chats/${chat.id}/messages`).send({ ciphertext: ct(), iv, burnSeconds: 30 });
      expect(sent.status).toBe(201);
      expect((await b.agent.get('/api/chats')).body[0].unread).toBe(1);
      const [m] = (await b.agent.get(`/api/chats/${chat.id}/messages`)).body;
      expect(m).toMatchObject({ fromMe: false, status: 'sent', ciphertext: ct(), burnSeconds: 30 });

      const got = await b.agent.post(`/api/messages/${m.id}/reveal`);
      expect(got.status).toBe(200);
      expect(got.body).toEqual({ ciphertext: ct(), iv });
      expect((await b.agent.post(`/api/messages/${m.id}/reveal`)).status).toBe(404);

      const [row] = await s.db.query('SELECT status, ciphertext, iv FROM messages WHERE id = ?', [m.id]);
      expect(row.status).toBe('burned');
      expect(row.ciphertext).toBeNull();
      expect(row.iv).toBeNull();
      const [aSees] = (await a.agent.get(`/api/chats/${chat.id}/messages`)).body;
      expect(aSees.status).toBe('burned');
      expect(aSees.ciphertext).toBeUndefined();
      expect((await b.agent.get('/api/chats')).body[0].unread).toBe(0);
    });
    it('20 simultaneous reveals produce exactly one success', async () => {
      const { a, b, chat } = await setup();
      const m = (await a.agent.post(`/api/chats/${chat.id}/messages`).send({ ciphertext: ct(), iv, burnSeconds: 15 })).body;
      const rs = await Promise.all(Array.from({ length: 20 }, () => b.agent.post(`/api/messages/${m.id}/reveal`)));
      expect(rs.filter((r) => r.status === 200)).toHaveLength(1);
    });
    it('the sender cannot reveal, and outsiders cannot read, send, or reveal', async () => {
      const { a, b, chat } = await setup();
      const c = await person('c@example.com', 'Cara', 'D'.repeat(43));
      const m = (await a.agent.post(`/api/chats/${chat.id}/messages`).send({ ciphertext: ct(), iv, burnSeconds: 30 })).body;
      expect((await a.agent.post(`/api/messages/${m.id}/reveal`)).status).toBe(404);
      expect((await c.agent.get(`/api/chats/${chat.id}`)).status).toBe(404);
      expect((await c.agent.get(`/api/chats/${chat.id}/messages`)).status).toBe(404);
      expect((await c.agent.post(`/api/chats/${chat.id}/messages`).send({ ciphertext: ct(), iv, burnSeconds: 30 })).status).toBe(404);
      expect((await c.agent.post(`/api/messages/${m.id}/reveal`)).status).toBe(404);
      expect((await b.agent.get(`/api/chats/${chat.id}/messages`)).body[0].status).toBe('sent'); // nothing was burned by the failed attempts
    });
    it('rejects bad messages', async () => {
      const { a, chat } = await setup();
      const send = (b: object) => a.agent.post(`/api/chats/${chat.id}/messages`).send(b);
      expect((await send({ ciphertext: ct(), iv, burnSeconds: 5 })).status).toBe(400);
      expect((await send({ ciphertext: 'not base64!', iv, burnSeconds: 30 })).status).toBe(400);
      expect((await send({ ciphertext: ct(), iv: Buffer.alloc(8).toString('base64'), burnSeconds: 30 })).status).toBe(400);
      expect((await send({ ciphertext: ct(70 * 1024), iv, burnSeconds: 30 })).status).toBe(400);
      expect((await a.agent.get('/api/chats/not-a-uuid/messages')).status).toBe(404);
    });
    it('unread messages are burned after 7 days', async () => {
      const { a, b, chat } = await setup();
      await a.agent.post(`/api/chats/${chat.id}/messages`).send({ ciphertext: ct(), iv, burnSeconds: 30 });
      clock += 8 * 24 * 3600 * 1000;
      expect(await s.accounts.expireMessages(clock)).toBe(1);
      expect((await b.agent.get(`/api/chats/${chat.id}/messages`)).body[0].status).toBe('burned');
    });
    it('the database never holds plaintext keys or passwords', async () => {
      const { a, chat } = await setup();
      await a.agent.post(`/api/chats/${chat.id}/messages`).send({ ciphertext: ct(), iv, burnSeconds: 30 });
      const users = JSON.stringify(await s.db.query('SELECT * FROM users'));
      expect(users).not.toContain('longpassword');
      expect(users).not.toContain('"d"'); // no private key material
    });
  });

  describe('live updates and erasure', () => {
    it('pushes a change event to both people when a message is sent', async () => {
      const { a, b, chat } = await (async () => {
        const a = await person('a@example.com', 'Amina');
        const b = await person('b@example.com', 'Brian', 'C'.repeat(43));
        return { a, b, chat: (await a.agent.post('/api/chats').send({ peerId: b.id })).body };
      })();
      const server = app.listen(0);
      const ac = new AbortController();
      try {
        const port = (server.address() as AddressInfo).port;
        const resp = await fetch(`http://127.0.0.1:${port}/api/events`, { headers: { cookie: b.cookie }, signal: ac.signal });
        expect(resp.headers.get('content-type')).toContain('text/event-stream');
        const reader = resp.body!.getReader();
        const read = async () => new TextDecoder().decode((await reader.read()).value);
        expect(await read()).toContain('retry');
        await a.agent.post(`/api/chats/${chat.id}/messages`).send({ ciphertext: ct(), iv, burnSeconds: 30 });
        const evt = await Promise.race([read(), new Promise<string>((r) => setTimeout(() => r('TIMEOUT'), 3000))]);
        expect(evt).toContain('"t":"change"');
        expect(evt).not.toContain(ct()); // events carry no message content
      } finally {
        ac.abort();
        hub.closeAll();
        server.close();
      }
    });
    it('the event stream needs a signed-in session', async () => {
      expect((await request(app).get('/api/events')).status).toBe(401);
    });
    it('deleting an account erases its sessions, chats and messages, and needs the password', async () => {
      const a = await person('a@example.com', 'Amina');
      const b = await person('b@example.com', 'Brian', 'C'.repeat(43));
      const chat = (await a.agent.post('/api/chats').send({ peerId: b.id })).body;
      await a.agent.post(`/api/chats/${chat.id}/messages`).send({ ciphertext: ct(), iv, burnSeconds: 30 });
      expect((await a.agent.delete('/api/me').send({ password: 'wrongpassword' })).status).toBe(401);
      expect((await a.agent.delete('/api/me').send({ password: 'longpassword' })).status).toBe(204);
      for (const t of ['messages', 'chats']) expect(Number((await s.db.query(`SELECT COUNT(*) AS c FROM ${t}`))[0].c)).toBe(0);
      expect((await s.db.query('SELECT id FROM users WHERE email = ?', ['a@example.com'])).length).toBe(0);
      expect((await a.agent.get('/api/me')).status).toBe(401);
      expect((await b.agent.get('/api/chats')).body).toHaveLength(0);
    });
  });
});
