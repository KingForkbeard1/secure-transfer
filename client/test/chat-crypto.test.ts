import { describe, it, expect } from 'vitest';
import { deriveConversationKey, generateDeviceKeyPair, safetyNumber } from '../src/crypto/chat';
import { decryptPayload, encryptPayload, payloadText, textPayload } from '../src/crypto';

describe('chat cryptography', () => {
  it('two devices derive the same key and can talk; a third device cannot read', async () => {
    const [a, b, c] = await Promise.all([generateDeviceKeyPair(), generateDeviceKeyPair(), generateDeviceKeyPair()]);
    const ka = await deriveConversationKey(a.privateKey, b.publicJwk);
    const kb = await deriveConversationKey(b.privateKey, a.publicJwk);
    const { ciphertext, iv } = await encryptPayload(ka, textPayload('door code 4821'));
    expect(payloadText(await decryptPayload(kb, ciphertext, iv))).toBe('door code 4821');
    const kc = await deriveConversationKey(c.privateKey, a.publicJwk);
    await expect(decryptPayload(kc, ciphertext, iv)).rejects.toThrow();
  });
  it('private keys cannot be exported, public keys carry no private part', async () => {
    const a = await generateDeviceKeyPair();
    await expect(crypto.subtle.exportKey('jwk', a.privateKey)).rejects.toThrow();
    expect(a.privateKey.extractable).toBe(false);
    expect((a.publicJwk as Record<string, unknown>).d).toBeUndefined();
  });
  it('safety number is the same for both people, differs per pair, and is 6 groups of 5 digits', async () => {
    const [a, b, c] = await Promise.all([generateDeviceKeyPair(), generateDeviceKeyPair(), generateDeviceKeyPair()]);
    const ab = await safetyNumber(a.publicJwk, b.publicJwk);
    expect(await safetyNumber(b.publicJwk, a.publicJwk)).toBe(ab);
    expect(await safetyNumber(a.publicJwk, c.publicJwk)).not.toBe(ab);
    expect(ab).toMatch(/^(\d{5} ){5}\d{5}$/);
  });
});
