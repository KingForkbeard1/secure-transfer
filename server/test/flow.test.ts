// End-to-end: real client crypto against the real API, as a browser would use them.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app';
import { LIMITS, makeStores, type Stores } from './helpers';
import {
  b64urlEncode, decryptPayload, deriveAesKey, deriveVerifier, encryptPayload, newLinkKey, newSalt,
  payloadText, textPayload, type Protection,
} from '../../client/src/crypto';

let app: ReturnType<typeof createApp>;
let s: Stores;
beforeEach(async () => {
  s = await makeStores('sqlite');
  app = createApp({ secrets: s.secrets, accounts: s.accounts, scryptN: 1024, limits: LIMITS });
});
afterEach(async () => { await s.db.close(); });

describe('full flow', () => {
  it('encrypt in the browser -> store -> reveal once -> decrypt; second reveal finds nothing', async () => {
    const secret = 'db_password = Kx9#mQ2vLp';
    const linkKey = newLinkKey();
    const key = await deriveAesKey(linkKey);
    const enc = await encryptPayload(key, textPayload(secret));
    const sent = { ...enc, kind: 'text', ttl: 86400 };

    // What the server receives contains neither the plaintext nor the link key.
    const wire = JSON.stringify(sent);
    expect(wire).not.toContain('Kx9');
    expect(wire).not.toContain(b64urlEncode(linkKey));

    const { id } = (await request(app).post('/api/secrets').send(sent)).body;
    const got = await request(app).post(`/api/secrets/${id}/reveal`).send({});
    expect(got.status).toBe(200);
    const plain = await decryptPayload(await deriveAesKey(linkKey), got.body.ciphertext, got.body.iv);
    expect(payloadText(plain)).toBe(secret);
    expect((await request(app).post(`/api/secrets/${id}/reveal`).send({})).status).toBe(404);
  });

  it('works with a passphrase; a wrong passphrase is refused before anything is destroyed', async () => {
    const linkKey = newLinkKey();
    const prot: Protection = { pass: 'correct horse', salt: newSalt(), iterations: 1000 };
    const enc = await encryptPayload(await deriveAesKey(linkKey, prot), textPayload('top secret'));
    const verifier = await deriveVerifier(prot);
    const { id } = (
      await request(app).post('/api/secrets').send({ ...enc, kind: 'text', ttl: 3600, salt: prot.salt, verifier })
    ).body;

    const meta = (await request(app).get(`/api/secrets/${id}`)).body;
    expect(meta.passphraseRequired).toBe(true);
    const wrongVerifier = await deriveVerifier({ pass: 'wrong', salt: meta.salt, iterations: 1000 });
    expect((await request(app).post(`/api/secrets/${id}/reveal`).send({ verifier: wrongVerifier })).status).toBe(401);

    const ok = await request(app).post(`/api/secrets/${id}/reveal`).send({ verifier });
    expect(ok.status).toBe(200);
    const key = await deriveAesKey(linkKey, { pass: 'correct horse', salt: meta.salt, iterations: 1000 });
    expect(payloadText(await decryptPayload(key, ok.body.ciphertext, ok.body.iv))).toBe('top secret');
  });

  it('transfers a 1 MB file intact', async () => {
    const data = new Uint8Array(1024 * 1024);
    for (let i = 0; i < data.length; i += 65536) crypto.getRandomValues(data.subarray(i, i + 65536));
    const linkKey = newLinkKey();
    const enc = await encryptPayload(await deriveAesKey(linkKey), { kind: 'file', name: 'report.pdf', mime: 'application/pdf', data });
    const { id } = (await request(app).post('/api/secrets').send({ ...enc, kind: 'file', ttl: 3600 })).body;
    const got = (await request(app).post(`/api/secrets/${id}/reveal`).send({})).body;
    const out = await decryptPayload(await deriveAesKey(linkKey), got.ciphertext, got.iv);
    expect(out.name).toBe('report.pdf');
    expect(Buffer.compare(Buffer.from(out.data), Buffer.from(data))).toBe(0);
  });
});
