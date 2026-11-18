import { describe, it, expect } from 'vitest';
import {
  b64urlDecode, b64urlEncode, deriveAesKey, deriveVerifier, decryptPayload, encryptPayload,
  newLinkKey, newSalt, packPayload, payloadText, textPayload, unpackPayload, b64d, b64e,
} from '../src/crypto';

const ITER = 1000; // fast for tests; production uses 600,000

describe('encoding', () => {
  it('base64url round trips arbitrary bytes', () => {
    const b = crypto.getRandomValues(new Uint8Array(1000));
    expect(b64urlDecode(b64urlEncode(b))).toEqual(b);
    expect(b64d(b64e(b))).toEqual(b);
    expect(b64urlEncode(b)).not.toMatch(/[+/=]/);
  });
  it('payload framing round trips', () => {
    const p = { kind: 'file' as const, name: 'a.pdf', mime: 'application/pdf', data: new Uint8Array([1, 2, 3]) };
    const q = unpackPayload(packPayload(p));
    expect(q.name).toBe('a.pdf');
    expect([...q.data]).toEqual([1, 2, 3]);
  });
});

describe('AES-256-GCM encryption', () => {
  it('round trips text', async () => {
    const k = await deriveAesKey(newLinkKey());
    const { ciphertext, iv } = await encryptPayload(k, textPayload('db_password = Kx9#mQ2vLp'));
    expect(payloadText(await decryptPayload(k, ciphertext, iv))).toBe('db_password = Kx9#mQ2vLp');
  });
  it('round trips binary files', async () => {
    const data = crypto.getRandomValues(new Uint8Array(200_000).subarray(0, 65_536));
    const k = await deriveAesKey(newLinkKey());
    const { ciphertext, iv } = await encryptPayload(k, { kind: 'file', name: 'x.bin', data });
    const out = await decryptPayload(k, ciphertext, iv);
    expect(out.name).toBe('x.bin');
    expect(out.data).toEqual(data);
  });
  it('uses a fresh IV and different ciphertext every time', async () => {
    const k = await deriveAesKey(newLinkKey());
    const a = await encryptPayload(k, textPayload('same'));
    const b = await encryptPayload(k, textPayload('same'));
    expect(a.iv).not.toBe(b.iv);
    expect(a.ciphertext).not.toBe(b.ciphertext);
  });
  it('fails with the wrong key', async () => {
    const k1 = await deriveAesKey(newLinkKey());
    const k2 = await deriveAesKey(newLinkKey());
    const { ciphertext, iv } = await encryptPayload(k1, textPayload('secret'));
    await expect(decryptPayload(k2, ciphertext, iv)).rejects.toThrow();
  });
  it('detects tampering (GCM authentication)', async () => {
    const k = await deriveAesKey(newLinkKey());
    const { ciphertext, iv } = await encryptPayload(k, textPayload('secret'));
    const bytes = b64d(ciphertext);
    bytes[5] ^= 1;
    await expect(decryptPayload(k, b64e(bytes), iv)).rejects.toThrow();
  });
});

describe('passphrase protection', () => {
  it('right passphrase decrypts, wrong one fails, link key alone fails', async () => {
    const linkKey = newLinkKey();
    const salt = newSalt();
    const good = { pass: 'correct horse', salt, iterations: ITER };
    const k = await deriveAesKey(linkKey, good);
    const { ciphertext, iv } = await encryptPayload(k, textPayload('top secret'));
    const again = await deriveAesKey(linkKey, good);
    expect(payloadText(await decryptPayload(again, ciphertext, iv))).toBe('top secret');
    const bad = await deriveAesKey(linkKey, { ...good, pass: 'wrong' });
    await expect(decryptPayload(bad, ciphertext, iv)).rejects.toThrow();
    const noPass = await deriveAesKey(linkKey);
    await expect(decryptPayload(noPass, ciphertext, iv)).rejects.toThrow();
  });
  it('verifier is deterministic, salt- and passphrase-dependent, and URL-safe', async () => {
    const salt = newSalt();
    const a = await deriveVerifier({ pass: 'pw', salt, iterations: ITER });
    expect(await deriveVerifier({ pass: 'pw', salt, iterations: ITER })).toBe(a);
    expect(await deriveVerifier({ pass: 'other', salt, iterations: ITER })).not.toBe(a);
    expect(await deriveVerifier({ pass: 'pw', salt: newSalt(), iterations: ITER })).not.toBe(a);
    expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
});
