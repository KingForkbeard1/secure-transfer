import { describe, it, expect, beforeEach } from 'vitest';
import { createMockChatService } from '../src/chat/mock';
import { memoryKeyStore } from '../src/chat/keystore';
import { ChatError } from '../src/chat/types';
import { deriveConversationKey, generateDeviceKeyPair } from '../src/crypto/chat';
import { decryptPayload, encryptPayload, payloadText, textPayload } from '../src/crypto';

class Mem implements Storage {
  private m = new Map<string, string>();
  get length() { return this.m.size; }
  clear() { this.m.clear(); }
  getItem(k: string) { return this.m.get(k) ?? null; }
  key(i: number) { return [...this.m.keys()][i] ?? null; }
  removeItem(k: string) { this.m.delete(k); }
  setItem(k: string, v: string) { this.m.set(k, v); }
}

let shared: Mem;
let clock: number;
const tab = () => createMockChatService({ storage: shared, session: new Mem(), now: () => clock, iterations: 1000 });
async function person(email: string, name: string) {
  const svc = tab();
  const u = await svc.register(email, 'longpassword', name);
  const keys = await generateDeviceKeyPair();
  await svc.setPublicKey(keys.publicJwk);
  return { svc, u, keys };
}
beforeEach(() => { shared = new Mem(); clock = 1_700_000_000_000; });

describe('accounts', () => {
  it('registers, rejects duplicates and weak input, logs in only with the right password', async () => {
    const s = tab();
    await s.register('Amina@Example.com', 'longpassword', 'Amina');
    await expect(tab().register('amina@example.com', 'longpassword', 'X')).rejects.toMatchObject({ code: 'email-taken' });
    await expect(tab().register('bad', 'longpassword', 'X')).rejects.toMatchObject({ code: 'invalid' });
    await expect(tab().register('b@example.com', 'short', 'X')).rejects.toMatchObject({ code: 'invalid' });
    const t = tab();
    await expect(t.login('amina@example.com', 'wrongpassword')).rejects.toBeInstanceOf(ChatError);
    await expect(t.login('nobody@example.com', 'longpassword')).rejects.toMatchObject({ code: 'bad-credentials' });
    expect((await t.login('AMINA@example.com', 'longpassword')).displayName).toBe('Amina');
    expect(await t.me()).not.toBeNull();
    await t.logout();
    expect(await t.me()).toBeNull();
  });
  it('never stores the password', async () => {
    await tab().register('a@example.com', 'my-secret-password', 'A');
    expect(shared.getItem('st.mock.db')).not.toContain('my-secret-password');
  });
});

describe('end-to-end encrypted chat with burn-after-reading', () => {
  it('A sends to B: server holds only ciphertext, B reveals once, then it is burned for both', async () => {
    const a = await person('a@example.com', 'Amina');
    const b = await person('b@example.com', 'Brian');
    const peerB = await a.svc.lookup('b@example.com');
    expect(peerB).not.toBeNull();
    const chat = await a.svc.openChat(peerB!.id);

    const key = await deriveConversationKey(a.keys.privateKey, peerB!.publicKey);
    const { ciphertext, iv } = await encryptPayload(key, textPayload('server login: hunter2'));
    await a.svc.send(chat.id, ciphertext, iv, 30);

    expect(shared.getItem('st.mock.db')).not.toContain('hunter2'); // the server never sees plaintext
    const bChat = (await b.svc.listChats())[0];
    expect(bChat.unread).toBe(1);

    const [msg] = await b.svc.messages(bChat.id);
    expect(msg.fromMe).toBe(false);
    const got = await b.svc.reveal(msg.id);
    expect(got).not.toBeNull();
    const bKey = await deriveConversationKey(b.keys.privateKey, (await b.svc.getChat(bChat.id)).peer.publicKey);
    expect(payloadText(await decryptPayload(bKey, got!.ciphertext, got!.iv))).toBe('server login: hunter2');

    expect(await b.svc.reveal(msg.id)).toBeNull(); // second reveal finds nothing
    expect((await b.svc.listChats())[0].unread).toBe(0);
    const [aSees] = await a.svc.messages(chat.id);
    expect(aSees.status).toBe('burned'); // sender sees it burned too
    expect(aSees.ciphertext).toBeUndefined();
    expect(shared.getItem('st.mock.db')).not.toContain(ciphertext); // ciphertext deleted from the store
  });
  it('the sender cannot reveal their own message and outsiders cannot read the chat', async () => {
    const a = await person('a@example.com', 'Amina');
    const b = await person('b@example.com', 'Brian');
    const c = await person('c@example.com', 'Cara');
    const chat = await a.svc.openChat(b.u.id);
    const m = await a.svc.send(chat.id, 'Y3Q=', 'aXY=', 30);
    expect(await a.svc.reveal(m.id)).toBeNull();
    await expect(c.svc.messages(chat.id)).rejects.toMatchObject({ code: 'not-found' });
    expect(await c.svc.reveal(m.id)).toBeNull();
    expect((await b.svc.messages(chat.id))[0].status).toBe('sent'); // the failed attempts burned nothing
  });
  it('rejects self-chat, unknown peers, bad burn times, and signed-out use', async () => {
    const a = await person('a@example.com', 'Amina');
    await expect(a.svc.openChat(a.u.id)).rejects.toMatchObject({ code: 'self-chat' });
    await expect(a.svc.openChat('missing')).rejects.toMatchObject({ code: 'not-found' });
    expect(await a.svc.lookup('a@example.com')).toBeNull();
    const b = await person('b@example.com', 'Brian');
    const chat = await a.svc.openChat(b.u.id);
    await expect(a.svc.send(chat.id, 'Y3Q=', 'aXY=', 5)).rejects.toMatchObject({ code: 'invalid' });
    await expect(tab().listChats()).rejects.toMatchObject({ code: 'not-signed-in' });
  });
  it('unread messages expire after 7 days', async () => {
    const a = await person('a@example.com', 'Amina');
    const b = await person('b@example.com', 'Brian');
    const chat = await a.svc.openChat(b.u.id);
    await a.svc.send(chat.id, 'Y3Q=', 'aXY=', 30);
    clock += 8 * 24 * 3600 * 1000;
    const [m] = await b.svc.messages(chat.id);
    expect(m.status).toBe('burned');
  });
  it('notifies subscribers when a message arrives', async () => {
    const a = await person('a@example.com', 'Amina');
    const b = await person('b@example.com', 'Brian');
    const chat = await a.svc.openChat(b.u.id);
    let n = 0;
    const off = a.svc.subscribe(() => n++);
    await a.svc.send(chat.id, 'Y3Q=', 'aXY=', 30);
    off();
    expect(n).toBeGreaterThan(0);
  });
});

describe('right to erasure', () => {
  it('deleting an account removes its chats and messages and needs the password', async () => {
    const a = await person('a@example.com', 'Amina');
    const b = await person('b@example.com', 'Brian');
    const chat = await a.svc.openChat(b.u.id);
    await a.svc.send(chat.id, 'Y3Q=', 'aXY=', 30);
    await expect(a.svc.deleteAccount('wrongpassword')).rejects.toMatchObject({ code: 'bad-credentials' });
    await a.svc.deleteAccount('longpassword');
    expect(await a.svc.me()).toBeNull();
    expect(await b.svc.listChats()).toHaveLength(0);
    expect(shared.getItem('st.mock.db')).not.toContain('a@example.com');
  });
});

describe('key storage', () => {
  it('memory key store round trips (the IndexedDB one is exercised in the UI test)', async () => {
    const ks = memoryKeyStore();
    expect(await ks.get('u')).toBeNull();
    const k = await generateDeviceKeyPair();
    await ks.put('u', k);
    expect((await ks.get('u'))!.publicJwk).toEqual(k.publicJwk);
  });
});
