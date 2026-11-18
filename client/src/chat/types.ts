export interface User { id: string; email: string; displayName: string; publicKey: JsonWebKey | null }
export interface Peer { id: string; email: string; displayName: string; publicKey: JsonWebKey }
export interface ChatSummary {
  id: string;
  peer: Peer;
  unread: number;
  last: { fromMe: boolean; status: 'sent' | 'burned'; at: number } | null;
}
export interface Message {
  id: string;
  chatId: string;
  fromMe: boolean;
  status: 'sent' | 'burned';
  ciphertext?: string; // present only while status === 'sent'
  iv?: string;
  burnSeconds: number;
  createdAt: number;
}
export type ChatErrorCode = 'email-taken' | 'bad-credentials' | 'not-signed-in' | 'not-found' | 'self-chat' | 'invalid' | 'rate-limited' | 'network';
export class ChatError extends Error {
  constructor(public code: ChatErrorCode) { super(code); }
}

/**
 * The only thing the chat UI talks to. `mock.ts` runs entirely in the browser; `remote.ts` talks to the server.
 * `remote.ts` implements the same methods over the real REST API plus server-sent events (see docs/PHASE2_API_CONTRACT.md).
 * The server only ever sees ciphertext, public keys and metadata.
 */
export interface ChatService {
  me(): Promise<User | null>;
  register(email: string, password: string, displayName: string): Promise<User>;
  login(email: string, password: string): Promise<User>;
  logout(): Promise<void>;
  setPublicKey(jwk: JsonWebKey): Promise<void>;
  lookup(email: string): Promise<Peer | null>;
  openChat(peerId: string): Promise<ChatSummary>;
  listChats(): Promise<ChatSummary[]>;
  getChat(chatId: string): Promise<ChatSummary>;
  messages(chatId: string): Promise<Message[]>;
  send(chatId: string, ciphertext: string, iv: string, burnSeconds: number): Promise<Message>;
  /** Atomic fetch-and-delete of the ciphertext. Returns null if already burned or not yours to open. */
  reveal(messageId: string): Promise<{ ciphertext: string; iv: string } | null>;
  /** Right to erasure: removes the account, its chats and messages. Needs the password. */
  deleteAccount(password: string): Promise<void>;
  subscribe(listener: () => void): () => void;
}
