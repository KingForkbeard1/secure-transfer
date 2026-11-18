import { ChatError, type ChatErrorCode, type ChatService, type ChatSummary, type Message, type Peer, type User } from './types';

export interface RemoteOptions {
  baseUrl?: string;
  fetch?: typeof fetch;
  /** Safety-net refresh interval in ms while signed in (live updates normally arrive by server-sent events). */
  pollMs?: number;
}

const CODES: Record<string, ChatErrorCode> = {
  'email-taken': 'email-taken', 'bad-credentials': 'bad-credentials', 'not-signed-in': 'not-signed-in',
  'not-found': 'not-found', gone: 'not-found', 'self-chat': 'self-chat', invalid: 'invalid', 'rate-limited': 'rate-limited',
};

/** Talks to the real server. The server only ever receives ciphertext, public keys and metadata. */
export function createRemoteChatService(opts: RemoteOptions = {}): ChatService {
  const base = opts.baseUrl ?? '';
  const doFetch: typeof fetch = opts.fetch ?? ((input, init) => fetch(input, init));
  const listeners = new Set<() => void>();
  let es: EventSource | null = null;
  let timer: ReturnType<typeof setInterval> | null = null;
  const emit = () => listeners.forEach((l) => l());

  const connect = () => {
    if (typeof EventSource !== 'undefined' && !es) { es = new EventSource(`${base}/api/events`); es.onmessage = emit; }
    if (!timer) timer = setInterval(emit, opts.pollMs ?? 30_000);
  };
  const disconnect = () => {
    es?.close(); es = null;
    if (timer) { clearInterval(timer); timer = null; }
  };

  async function call(method: string, path: string, body?: unknown): Promise<{ status: number; data: any }> { // eslint-disable-line @typescript-eslint/no-explicit-any
    let res: Response;
    try {
      res = await doFetch(`${base}${path}`, {
        method,
        credentials: 'same-origin',
        headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch {
      throw new ChatError('network');
    }
    let data: unknown = null;
    try { data = await res.json(); } catch { /* empty body */ }
    return { status: res.status, data };
  }
  const fail = (status: number, data: unknown): never => {
    const code = (data as { error?: string } | null)?.error ?? '';
    throw new ChatError(CODES[code] ?? (status === 401 ? 'not-signed-in' : status === 404 ? 'not-found' : status === 429 ? 'rate-limited' : 'invalid'));
  };
  const ok = async (method: string, path: string, body: unknown, good: number[]) => {
    const r = await call(method, path, body);
    if (!good.includes(r.status)) fail(r.status, r.data);
    return r.data;
  };

  return {
    async me() {
      const r = await call('GET', '/api/me');
      if (r.status === 200) { connect(); return r.data as User; }
      disconnect();
      return null;
    },
    async register(email, password, displayName) {
      const u = (await ok('POST', '/api/auth/register', { email, password, displayName }, [201])) as User;
      connect(); emit();
      return u;
    },
    async login(email, password) {
      const u = (await ok('POST', '/api/auth/login', { email, password }, [200])) as User;
      connect(); emit();
      return u;
    },
    async logout() { await call('POST', '/api/auth/logout'); disconnect(); emit(); },
    async setPublicKey(jwk) { await ok('PUT', '/api/me/key', { jwk }, [204]); emit(); },
    async lookup(email) {
      const r = await call('GET', `/api/users/lookup?email=${encodeURIComponent(email.trim())}`);
      if (r.status === 200) return r.data as Peer;
      if (r.status === 404) return null;
      return fail(r.status, r.data);
    },
    async openChat(peerId) { return (await ok('POST', '/api/chats', { peerId }, [200])) as ChatSummary; },
    async listChats() { return (await ok('GET', '/api/chats', undefined, [200])) as ChatSummary[]; },
    async getChat(chatId) { return (await ok('GET', `/api/chats/${encodeURIComponent(chatId)}`, undefined, [200])) as ChatSummary; },
    async messages(chatId) { return (await ok('GET', `/api/chats/${encodeURIComponent(chatId)}/messages`, undefined, [200])) as Message[]; },
    async send(chatId, ciphertext, iv, burnSeconds) {
      const m = (await ok('POST', `/api/chats/${encodeURIComponent(chatId)}/messages`, { ciphertext, iv, burnSeconds }, [201])) as Message;
      emit();
      return m;
    },
    async reveal(messageId) {
      const r = await call('POST', `/api/messages/${encodeURIComponent(messageId)}/reveal`);
      if (r.status === 200) { emit(); return r.data as { ciphertext: string; iv: string }; }
      if (r.status === 404) return null;
      return fail(r.status, r.data);
    },
    async deleteAccount(password) { await ok('DELETE', '/api/me', { password }, [204]); disconnect(); emit(); },
    subscribe(listener) {
      listeners.add(listener);
      return () => { listeners.delete(listener); };
    },
  };
}
