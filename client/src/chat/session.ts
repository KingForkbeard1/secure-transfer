import { useEffect, useState } from 'react';
import { generateDeviceKeyPair } from '../crypto/chat';
import { idbKeyStore, type DeviceKeys, type KeyStore } from './keystore';
import { createMockChatService } from './mock';
import { createRemoteChatService } from './remote';
import type { ChatService, User } from './types';

/** Real server by default. Set VITE_CHAT_BACKEND=mock to run the chats entirely in the browser (used by the UI tests). */
export const chat: ChatService = import.meta.env.VITE_CHAT_BACKEND === 'mock' ? createMockChatService() : createRemoteChatService();
export const keyStore: KeyStore = idbKeyStore();

const same = (a: JsonWebKey | null | undefined, b: JsonWebKey) => !!a && a.x === b.x && a.y === b.y;

/** Makes sure this device has a key pair and the server knows its public half. A new device means old chats stay unreadable. */
export async function ensureDeviceKeys(svc: ChatService, ks: KeyStore, user: User): Promise<DeviceKeys> {
  let k = await ks.get(user.id);
  if (!k) {
    k = await generateDeviceKeyPair();
    await ks.put(user.id, k);
    await svc.setPublicKey(k.publicJwk);
  } else if (!same(user.publicKey, k.publicJwk)) {
    await svc.setPublicKey(k.publicJwk);
  }
  return k;
}

/** undefined = still loading, null = signed out. */
export function useSession(): User | null | undefined {
  const [user, setUser] = useState<User | null | undefined>(undefined);
  useEffect(() => {
    let live = true;
    const load = async () => {
      try {
        const u = await chat.me();
        if (u) await ensureDeviceKeys(chat, keyStore, u);
        if (live) setUser(u);
      } catch {
        if (live) setUser(null);
      }
    };
    load();
    const off = chat.subscribe(() => { load(); });
    return () => { live = false; off(); };
  }, []);
  return user;
}

export function useUnread(user: User | null | undefined): number {
  const [n, setN] = useState(0);
  useEffect(() => {
    if (!user) { setN(0); return; }
    let live = true;
    const load = () => chat.listChats().then((c) => live && setN(c.reduce((a, x) => a + x.unread, 0))).catch(() => {});
    load();
    const off = chat.subscribe(load);
    return () => { live = false; off(); };
  }, [user]);
  return n;
}
