// The real front-end chat code + real encryption, talking to the real server over real HTTP, for two people.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { createApp } from '../src/app';
import { EventHub } from '../src/events';
import { createRemoteChatService } from '../../client/src/chat/remote';
import { memoryKeyStore } from '../../client/src/chat/keystore';
import { ChatError } from '../../client/src/chat/types';
import { deriveConversationKey, generateDeviceKeyPair, safetyNumber } from '../../client/src/crypto/chat';
import { decryptPayload, encryptPayload, payloadText, textPayload } from '../../client/src/crypto';
import { KINDS, LIMITS, makeStores, type Stores } from './helpers';

/** Node's fetch has no cookie jar, so each "browser" gets its own. */
function browser(base: string): typeof fetch {
  let cookie = '';
  return async (input, init = {}) => {
    const h = new Headers(init.headers);
    if (cookie) h.set('cookie', cookie);
    const r = await fetch(base + String(input), { ...init, headers: h });
    for (const c of r.headers.getSetCookie()) cookie = /Max-Age=0|Expires=Thu, 01 Jan 1970/i.test(c) ? '' : c.split(';')[0];
    return r;
  };
}

for (const kind of KINDS) describe(`front end <-> server on ${kind}`, () => {
  let s: Stores;
  let server: Server;
  let hub: EventHub;
  let base: string;
  beforeEach(async () => {
    s = await makeStores(kind);
    hub = new EventHub();
    server = createApp({ secrets: s.secrets, accounts: s.accounts, hub, scryptN: 1024, limits: LIMITS }).listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterEach(async () => { hub.closeAll(); server.close(); await s.db.close(); });

  const mkService = () => createRemoteChatService({ fetch: browser(base), pollMs: 60_000 });
  async function join(email: string, name: string) {
    const svc = mkService();
    const user = await svc.register(email, 'longpassword', name);
    const keys = await generateDeviceKeyPair();
    const ks = memoryKeyStore();
    await ks.put(user.id, keys);
    await svc.setPublicKey(keys.publicJwk);
    return { svc, user, keys };
  }

  it('two people chat: encrypted on the device, ciphertext on the server, burned on reading', async () => {
    const alice = await join('alice@example.com', 'Alice');
    const bob = await join('bob@example.com', 'Bob');

    // Alice finds Bob by exact email and starts a chat
    expect(await alice.svc.lookup('nobody@example.com')).toBeNull();
    const peer = await alice.svc.lookup('bob@example.com');
    expect(peer?.displayName).toBe('Bob');
    const chat = await alice.svc.openChat(peer!.id);

    // Alice encrypts with the key only she and Bob can derive, and sends
    const aliceKey = await deriveConversationKey(alice.keys.privateKey, peer!.publicKey);
    const enc = await encryptPayload(aliceKey, textPayload('server login: hunter2'));
    await alice.svc.send(chat.id, enc.ciphertext, enc.iv, 30);

    // The server's database holds ciphertext only
    const stored = JSON.stringify(await s.db.query('SELECT sender_id, status FROM messages'));
    expect(stored).not.toContain('hunter2');
    const [raw] = await s.db.query('SELECT ciphertext FROM messages');
    expect(Buffer.from(raw.ciphertext).includes(Buffer.from('hunter2'))).toBe(false);

    // Bob sees an unread chat, reveals once, and decrypts with his own key
    const bobChats = await bob.svc.listChats();
    expect(bobChats[0].unread).toBe(1);
    const [msg] = await bob.svc.messages(bobChats[0].id);
    const got = await bob.svc.reveal(msg.id);
    expect(got).not.toBeNull();
    const bobKey = await deriveConversationKey(bob.keys.privateKey, bobChats[0].peer.publicKey);
    expect(payloadText(await decryptPayload(bobKey, got!.ciphertext, got!.iv))).toBe('server login: hunter2');

    // Second reveal finds nothing; both people now see it burned; the row has no ciphertext left
    expect(await bob.svc.reveal(msg.id)).toBeNull();
    expect((await alice.svc.messages(chat.id))[0]).toMatchObject({ status: 'burned', fromMe: true });
    const [after] = await s.db.query('SELECT ciphertext FROM messages');
    expect(after.ciphertext).toBeNull();

    // Both see the same safety number
    expect(await safetyNumber(alice.keys.publicJwk, peer!.publicKey)).toBe(await safetyNumber(bob.keys.publicJwk, alice.user.publicKey ?? alice.keys.publicJwk));
  });

  it('maps server errors to the codes the screens expect', async () => {
    await join('a@example.com', 'A');
    const other = mkService();
    await expect(other.login('a@example.com', 'wrongpassword')).rejects.toMatchObject({ code: 'bad-credentials' });
    await expect(other.register('a@example.com', 'longpassword', 'Dup')).rejects.toMatchObject({ code: 'email-taken' });
    await expect(other.register('bad', 'longpassword', 'X')).rejects.toMatchObject({ code: 'invalid' });
    await expect(other.listChats()).rejects.toMatchObject({ code: 'not-signed-in' });
    expect(await other.me()).toBeNull();
    const down = createRemoteChatService({ fetch: async () => { throw new Error('offline'); } });
    await expect(down.me()).rejects.toBeInstanceOf(ChatError);
  });

  it('sign out, sign in again, and delete the account', async () => {
    const a = await join('a@example.com', 'A');
    await a.svc.logout();
    expect(await a.svc.me()).toBeNull();
    expect((await a.svc.login('a@example.com', 'longpassword')).displayName).toBe('A');
    await expect(a.svc.deleteAccount('wrongpassword')).rejects.toMatchObject({ code: 'bad-credentials' });
    await a.svc.deleteAccount('longpassword');
    expect(await a.svc.me()).toBeNull();
    expect((await s.db.query('SELECT id FROM users')).length).toBe(0);
  });

  it('notifies listeners after the user acts', async () => {
    const a = await join('a@example.com', 'A');
    const b = await join('b@example.com', 'B');
    const chat = await a.svc.openChat((await a.svc.lookup('b@example.com'))!.id);
    let n = 0;
    const off = a.svc.subscribe(() => n++);
    await a.svc.send(chat.id, Buffer.alloc(40, 1).toString('base64'), Buffer.alloc(12, 1).toString('base64'), 15);
    off();
    expect(n).toBeGreaterThan(0);
    expect(b.user.displayName).toBe('B');
  });
});
