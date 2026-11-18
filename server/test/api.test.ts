import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import request from 'supertest';
import { createApp, MAX_CIPHERTEXT_BYTES } from '../src/app';
import { MAX_ATTEMPTS } from '../src/store';
import { KINDS, LIMITS, makeStores, type Stores } from './helpers';

const ct = (n = 64) => Buffer.alloc(n, 7).toString('base64');
const iv = Buffer.alloc(12, 3).toString('base64');
const body = (extra: object = {}) => ({ ciphertext: ct(), iv, kind: 'text', ttl: 3600, ...extra });
const ID = /^[A-Za-z0-9_-]{22}$/;

for (const kind of KINDS) describe(`Phase 1 API on ${kind}`, () => {
let s: Stores;
let clock: number;
const make = (limits = {}) =>
  createApp({ secrets: s.secrets, accounts: s.accounts, now: () => clock, scryptN: 1024, limits: { ...LIMITS, ...limits } });

beforeEach(async () => {
  s = await makeStores(kind);
  clock = 1_700_000_000_000;
});
afterEach(async () => { await s.db.close(); });

describe('create + metadata', () => {
  it('creates a secret and returns an unguessable id', async () => {
    const r = await request(make()).post('/api/secrets').send(body());
    expect(r.status).toBe(201);
    expect(r.body.id).toMatch(ID);
    expect(r.body.expiresAt).toBe(clock + 3600_000);
  });
  it('GET never burns the secret, however many times it is called', async () => {
    const app = make();
    const { id } = (await request(app).post('/api/secrets').send(body())).body;
    for (let i = 0; i < 3; i++) {
      const g = await request(app).get(`/api/secrets/${id}`);
      expect(g.status).toBe(200);
      expect(g.body).toEqual({ kind: 'text', passphraseRequired: false, salt: null });
    }
    expect((await request(app).post(`/api/secrets/${id}/reveal`).send({})).status).toBe(200);
  });
  it('unknown or malformed ids look the same: 404', async () => {
    const app = make();
    expect((await request(app).get('/api/secrets/abc')).status).toBe(404);
    expect((await request(app).get(`/api/secrets/${'a'.repeat(22)}`)).status).toBe(404);
  });
});

describe('reveal burns exactly once', () => {
  it('returns the stored ciphertext, then the record is gone', async () => {
    const app = make();
    const { id } = (await request(app).post('/api/secrets').send(body())).body;
    const r1 = await request(app).post(`/api/secrets/${id}/reveal`).send({});
    expect(r1.status).toBe(200);
    expect(r1.body).toEqual({ ciphertext: ct(), iv, kind: 'text' });
    expect((await request(app).post(`/api/secrets/${id}/reveal`).send({})).status).toBe(404);
    expect((await request(app).get(`/api/secrets/${id}`)).status).toBe(404);
    expect((await request(app).get(`/api/secrets/${id}/status`)).body.status).toBe('opened');
    expect(Number((await s.db.query('SELECT COUNT(*) AS c FROM secrets'))[0].c)).toBe(0);
  });
  it('20 parallel reveals produce exactly one success', async () => {
    const app = make();
    const { id } = (await request(app).post('/api/secrets').send(body())).body;
    const results = await Promise.all(
      Array.from({ length: 20 }, () => request(app).post(`/api/secrets/${id}/reveal`).send({})),
    );
    expect(results.filter((r) => r.status === 200)).toHaveLength(1);
    expect(results.filter((r) => r.status === 404)).toHaveLength(19);
  });
});

describe('expiry', () => {
  it('expired secrets cannot be read or revealed', async () => {
    const app = make();
    const { id } = (await request(app).post('/api/secrets').send(body())).body;
    clock += 3601_000;
    expect((await request(app).get(`/api/secrets/${id}`)).status).toBe(404);
    expect((await request(app).get(`/api/secrets/${id}/status`)).body.status).toBe('expired');
    expect((await request(app).post(`/api/secrets/${id}/reveal`).send({})).status).toBe(404);
  });
  it('the sweeper destroys unopened expired secrets and leaves a content-free tombstone', async () => {
    const app = make();
    const a = (await request(app).post('/api/secrets').send(body())).body.id;
    const b = (await request(app).post('/api/secrets').send(body({ ttl: 86400 }))).body.id;
    clock += 3601_000;
    expect(await s.secrets.sweep(clock)).toBe(1);
    expect(Number((await s.db.query('SELECT COUNT(*) AS c FROM secrets WHERE id = ?', [a]))[0].c)).toBe(0);
    expect((await request(app).get(`/api/secrets/${a}/status`)).body.status).toBe('expired');
    expect((await request(app).get(`/api/secrets/${b}/status`)).body.status).toBe('waiting');
    clock += 8 * 24 * 3600_000;
    await s.secrets.sweep(clock);
    expect((await request(app).get(`/api/secrets/${a}/status`)).status).toBe(404);
  });
});

describe('passphrase protection', () => {
  const salt = Buffer.alloc(16, 9).toString('base64');
  const verifier = 'v'.repeat(43);
  const wrong = 'w'.repeat(43);
  it('advertises the salt, counts failures, and accepts the right verifier', async () => {
    const app = make();
    const { id } = (await request(app).post('/api/secrets').send(body({ salt, verifier }))).body;
    const meta = await request(app).get(`/api/secrets/${id}`);
    expect(meta.body).toEqual({ kind: 'text', passphraseRequired: true, salt });
    const r0 = await request(app).post(`/api/secrets/${id}/reveal`).send({});
    expect([r0.status, r0.body.attemptsLeft]).toEqual([401, MAX_ATTEMPTS - 1]);
    const r1 = await request(app).post(`/api/secrets/${id}/reveal`).send({ verifier: wrong });
    expect([r1.status, r1.body.attemptsLeft]).toEqual([401, MAX_ATTEMPTS - 2]);
    expect((await request(app).post(`/api/secrets/${id}/reveal`).send({ verifier })).status).toBe(200);
  });
  it('burns the secret after 5 wrong attempts, even if the 6th is correct', async () => {
    const app = make();
    const { id } = (await request(app).post('/api/secrets').send(body({ salt, verifier }))).body;
    for (let i = 0; i < MAX_ATTEMPTS; i++) {
      expect((await request(app).post(`/api/secrets/${id}/reveal`).send({ verifier: wrong })).status).toBe(401);
    }
    expect((await request(app).post(`/api/secrets/${id}/reveal`).send({ verifier })).status).toBe(404);
    expect((await request(app).get(`/api/secrets/${id}/status`)).body.status).toBe('expired');
  });
  it('stores only a hash of the verifier, never the verifier itself', async () => {
    const app = make();
    const { id } = (await request(app).post('/api/secrets').send(body({ salt, verifier }))).body;
    const row = (await s.db.query('SELECT verifier_hash AS h FROM secrets WHERE id = ?', [id]))[0] as { h: string };
    expect(row.h).toHaveLength(64);
    expect(row.h).not.toContain(verifier);
  });
});

describe('validation and limits', () => {
  it('rejects malformed requests', async () => {
    const app = make();
    const salt = Buffer.alloc(16, 9).toString('base64');
    const bad = [
      {}, body({ ttl: 999 }), body({ kind: 'video' }), body({ iv: Buffer.alloc(8).toString('base64') }),
      body({ ciphertext: 'not base64!!' }), body({ salt }), body({ verifier: 'x'.repeat(30) }),
    ];
    for (const b of bad) expect((await request(app).post('/api/secrets').send(b)).status).toBe(400);
  });
  it('rejects ciphertext over the 5 MB limit but accepts a 5 MB payload', async () => {
    const app = make();
    const over = await request(app).post('/api/secrets').send(body({ ciphertext: ct(MAX_CIPHERTEXT_BYTES + 1) }));
    expect(over.status).toBe(400);
    const ok = await request(app).post('/api/secrets').send(body({ ciphertext: ct(5 * 1024 * 1024 + 100), kind: 'file' }));
    expect(ok.status).toBe(201);
  });
  it('rejects oversized request bodies with 413', async () => {
    const r = await request(make()).post('/api/secrets').send({ ciphertext: 'A'.repeat(9 * 1024 * 1024) });
    expect(r.status).toBe(413);
  });
  it('rate-limits secret creation', async () => {
    const app = make({ create: 2 });
    expect((await request(app).post('/api/secrets').send(body())).status).toBe(201);
    expect((await request(app).post('/api/secrets').send(body())).status).toBe(201);
    expect((await request(app).post('/api/secrets').send(body())).status).toBe(429);
  });
  it('sends security headers and disables caching on the API', async () => {
    const r = await request(make()).get('/api/health');
    expect(r.headers['content-security-policy']).toContain("default-src 'self'");
    expect(r.headers['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(r.headers['cache-control']).toBe('no-store');
    expect(r.headers['x-powered-by']).toBeUndefined();
    expect(r.headers['referrer-policy']).toBe('no-referrer');
  });
});
});
