// @vitest-environment jsdom
import 'fake-indexeddb/auto';
import { webcrypto } from 'node:crypto';
import { describe, it, expect, afterEach } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';

Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });

import App from '../src/App';
import { createMockChatService } from '../src/chat/mock';
import { deriveConversationKey, generateDeviceKeyPair } from '../src/crypto/chat';
import { encryptPayload, textPayload } from '../src/crypto';

class Mem implements Storage {
  private m = new Map<string, string>();
  get length() { return this.m.size; }
  clear() { this.m.clear(); }
  getItem(k: string) { return this.m.get(k) ?? null; }
  key(i: number) { return [...this.m.keys()][i] ?? null; }
  removeItem(k: string) { this.m.delete(k); }
  setItem(k: string, v: string) { this.m.set(k, v); }
}
const go = (p: string) => { history.pushState(null, '', p); };
const poke = () => window.dispatchEvent(new StorageEvent('storage', { key: 'st.mock.db' })); // another tab changed the data
const type = (el: HTMLElement, value: string) => fireEvent.change(el, { target: { value } });

afterEach(cleanup);

describe('Phase 2 screens, driven like a user', () => {
  it('sign up, start a chat, exchange encrypted burn-after-reading messages, verify, sign out', async () => {
    go('/chats');
    render(<App />);

    // signed out -> sign-in screen
    await screen.findByText('Sign in to secret chats');
    fireEvent.click(screen.getByText('New here? Create an account'));
    type(screen.getByPlaceholderText('Email'), 'alice@example.com');
    type(screen.getByPlaceholderText('Display name'), 'Alice');
    type(screen.getByPlaceholderText('Password (8+ characters)'), 'longpassword');
    fireEvent.click(screen.getByRole('button', { name: 'Create account' }));
    await screen.findByText('Secret chats', {}, { timeout: 5000 });
    await screen.findByText(/No chats yet/);

    // Bob is a second person (another tab), with his own device key
    const bob = createMockChatService({ storage: localStorage, session: new Mem(), iterations: 1000 });
    const bobUser = await bob.register('bob@example.com', 'longpassword', 'Bob');
    const bobKeys = await generateDeviceKeyPair();
    await bob.setPublicKey(bobKeys.publicJwk);

    // unknown email is handled
    type(screen.getByLabelText('Email of the person to chat with'), 'nobody@example.com');
    fireEvent.click(screen.getByRole('button', { name: 'Start' }));
    await screen.findByText(/No one with that email/);

    // start a real chat with Bob
    type(screen.getByLabelText('Email of the person to chat with'), 'bob@example.com');
    fireEvent.click(screen.getByRole('button', { name: 'Start' }));
    await screen.findByText('Encrypted on both devices', {}, { timeout: 5000 });

    // Alice sends a message: she sees it, the "server" must not contain the plaintext
    type(screen.getByLabelText('Message'), 'hello bob, the code is 4821');
    await waitFor(() => expect((screen.getByRole('button', { name: 'Send' }) as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(screen.getByRole('button', { name: 'Send' }));
    await screen.findByText('hello bob, the code is 4821');
    await screen.findByText('Not opened yet');
    expect(localStorage.getItem('st.mock.db')).not.toContain('4821');

    // Bob sends back (encrypted with his side of the conversation key)
    const alice = await bob.lookup('alice@example.com');
    const chat = await bob.openChat(alice!.id);
    const key = await deriveConversationKey(bobKeys.privateKey, alice!.publicKey);
    const enc = await encryptPayload(key, textPayload('server login: hunter2'));
    await bob.send(chat.id, enc.ciphertext, enc.iv, 15);
    poke();

    // Alice sees a hidden message, reveals it once, and it counts down
    const reveal = await screen.findByRole('button', { name: /Tap to reveal/ });
    expect(screen.queryByText('server login: hunter2')).toBeNull();
    fireEvent.click(reveal);
    await screen.findByText('server login: hunter2');
    expect(screen.getByText(/Burns in \d+ s/)).toBeTruthy();
    expect(localStorage.getItem('st.mock.db')).not.toContain('hunter2');
    expect(localStorage.getItem('st.mock.db')).not.toContain(enc.ciphertext); // ciphertext deleted on reveal

    // safety number
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }));
    await waitFor(() => expect(screen.getByText(/^(\d{5} ){5}\d{5}$/)).toBeTruthy());

    // Bob sees Alice's message as unread, and the chat list shows the badge
    expect((await bob.listChats())[0].unread).toBe(1);
    expect(bobUser.displayName).toBe('Bob');

    // settings + sign out
    fireEvent.click(within(screen.getByRole('navigation')).getByText('Settings'));
    fireEvent.click(await screen.findByRole('button', { name: /Sign out \(Alice\)/ }));
    fireEvent.click(within(screen.getByRole('navigation')).getByText('Chats'));
    await screen.findByText('Sign in to secret chats');
  }, 30000);
});
