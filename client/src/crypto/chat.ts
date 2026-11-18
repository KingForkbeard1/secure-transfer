/**
 * Phase 2 chat cryptography (all in the browser, Web Crypto only).
 *  - each device holds an ECDH P-256 key pair; the private key is non-extractable
 *  - conversation key = HKDF(ECDH(myPrivate, peerPublic)) -> AES-256-GCM (see index.ts)
 *  - safety number: both people can compare it out of band to detect a swapped key
 * Limitation (state it in the report): no forward secrecy, and a new device cannot read old chats.
 */
import { hkdf } from './index';

const CURVE = { name: 'ECDH', namedCurve: 'P-256' } as const;

export async function generateDeviceKeyPair(): Promise<{ privateKey: CryptoKey; publicJwk: JsonWebKey }> {
  const pair = (await crypto.subtle.generateKey(CURVE, false, ['deriveBits'])) as CryptoKeyPair;
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey); // public keys are always exportable
  return { privateKey: pair.privateKey, publicJwk: { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x, y: publicJwk.y } };
}

export async function deriveConversationKey(privateKey: CryptoKey, peerPublic: JsonWebKey): Promise<CryptoKey> {
  const pub = await crypto.subtle.importKey('jwk', peerPublic, CURVE, false, []);
  const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: pub }, privateKey, 256));
  const raw = await hkdf(bits, 'secure-transfer/v1/chat-key');
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

const canon = (k: JsonWebKey) => `${k.x}.${k.y}`;

/** Six groups of five digits, identical for both people in a conversation. */
export async function safetyNumber(a: JsonWebKey, b: JsonWebKey): Promise<string> {
  const [first, second] = [canon(a), canon(b)].sort();
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${first}|${second}`)));
  const groups: string[] = [];
  for (let i = 0; i < 6; i++) {
    const n = ((digest[i * 4] << 24) | (digest[i * 4 + 1] << 16) | (digest[i * 4 + 2] << 8) | digest[i * 4 + 3]) >>> 0;
    groups.push(String(n % 100000).padStart(5, '0'));
  }
  return groups.join(' ');
}
