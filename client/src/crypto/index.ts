/**
 * All encryption happens here, in the browser, using the Web Crypto API.
 * The server only ever receives ciphertext. No custom cryptography.
 *
 *  link key (K1)   32 random bytes, lives only in the URL fragment (#...)
 *  passphrase (P)  optional; K2 = PBKDF2-SHA256(P, salt, 600k)
 *  AES key         HKDF-SHA256(K1 || K2)  -> AES-256-GCM, random 96-bit IV per message
 *  verifier        HKDF-SHA256(K2, other label); the server stores only a hash of it
 */
const enc = new TextEncoder();
const dec = new TextDecoder();

export const PBKDF2_ITERATIONS = 600_000;
export const MAX_FILE_BYTES = 5 * 1024 * 1024;

export function b64e(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
export function b64d(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
export const b64urlEncode = (b: Uint8Array) => b64e(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export const b64urlDecode = (s: string) => b64d(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4));

export const newLinkKey = () => crypto.getRandomValues(new Uint8Array(32));
export const newSalt = () => b64e(crypto.getRandomValues(new Uint8Array(16)));

export interface Protection { pass: string; salt: string; iterations?: number }

export async function hkdf(ikm: Uint8Array, info: string): Promise<ArrayBuffer> {
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode(info) }, k, 256);
}

async function passwordKey(p: Protection): Promise<Uint8Array> {
  const base = await crypto.subtle.importKey('raw', enc.encode(p.pass.normalize('NFKC')), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: b64d(p.salt), iterations: p.iterations ?? PBKDF2_ITERATIONS },
    base,
    256,
  );
  return new Uint8Array(bits);
}

export async function deriveAesKey(linkKey: Uint8Array, p?: Protection): Promise<CryptoKey> {
  let ikm = linkKey;
  if (p) {
    const k2 = await passwordKey(p);
    ikm = new Uint8Array(linkKey.length + k2.length);
    ikm.set(linkKey);
    ikm.set(k2, linkKey.length);
  }
  const raw = await hkdf(ikm, 'secure-transfer/v1/aes-key');
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/** Proves knowledge of the passphrase to the server without revealing it or any key. */
export async function deriveVerifier(p: Protection): Promise<string> {
  const k2 = await passwordKey(p);
  return b64urlEncode(new Uint8Array(await hkdf(k2, 'secure-transfer/v1/verifier')));
}

export interface Payload { kind: 'text' | 'file'; name?: string; mime?: string; data: Uint8Array }

export function packPayload(p: Payload): Uint8Array {
  const header = enc.encode(JSON.stringify({ kind: p.kind, name: p.name, mime: p.mime }));
  const out = new Uint8Array(4 + header.length + p.data.length);
  new DataView(out.buffer).setUint32(0, header.length);
  out.set(header, 4);
  out.set(p.data, 4 + header.length);
  return out;
}
export function unpackPayload(b: Uint8Array): Payload {
  if (b.length < 4) throw new Error('bad payload');
  const len = new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(0);
  if (len > b.length - 4) throw new Error('bad payload');
  const h = JSON.parse(dec.decode(b.subarray(4, 4 + len))) as { kind: 'text' | 'file'; name?: string; mime?: string };
  return { kind: h.kind, name: h.name, mime: h.mime, data: b.subarray(4 + len) };
}

export async function encryptPayload(key: CryptoKey, p: Payload): Promise<{ ciphertext: string; iv: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, packPayload(p)));
  return { ciphertext: b64e(ct), iv: b64e(iv) };
}
export async function decryptPayload(key: CryptoKey, ciphertext: string, iv: string): Promise<Payload> {
  const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64d(iv) }, key, b64d(ciphertext)));
  return unpackPayload(pt);
}
export const textPayload = (s: string): Payload => ({ kind: 'text', data: enc.encode(s) });
export const payloadText = (p: Payload) => dec.decode(p.data);
