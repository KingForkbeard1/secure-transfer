// @vitest-environment jsdom
import 'fake-indexeddb/auto';
import { webcrypto } from 'node:crypto';
import { describe, it, expect, afterEach, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';

Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });
import App from '../src/App';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe('Receive tab', () => {
  it('rejects junk, then opens a pasted link on the reveal screen with the key kept in the address fragment', async () => {
    history.pushState(null, '', '/receive');
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ kind: 'text', passphraseRequired: false, salt: null }), { status: 200 })));
    render(<App />);
    const box = await screen.findByLabelText('One-time link');

    fireEvent.change(box, { target: { value: 'not a link' } });
    fireEvent.click(screen.getByRole('button', { name: 'Open link' }));
    await screen.findByText(/does not look like a Secure Transfer link/);

    const id = 'FZpzw3mBJF9FcpazViN0RQ';
    const key = 'B'.repeat(43);
    fireEvent.change(box, { target: { value: `Here: https://example.com/s/${id}#${key}` } });
    fireEvent.click(screen.getByRole('button', { name: 'Open link' }));

    await screen.findByText('You’ve received a secret');
    expect(location.pathname).toBe(`/s/${id}`);
    expect(location.hash).toBe(`#${key}`);
    expect(screen.getByRole('button', { name: 'Reveal message' })).toBeTruthy();
  });

  it('shows "Nothing here" when the pasted link was already used', async () => {
    history.pushState(null, '', '/receive');
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: 'gone' }), { status: 404 })));
    render(<App />);
    fireEvent.change(await screen.findByLabelText('One-time link'), { target: { value: `/s/FZpzw3mBJF9FcpazViN0RQ#${'C'.repeat(43)}` } });
    fireEvent.click(screen.getByRole('button', { name: 'Open link' }));
    await screen.findByText('Nothing here');
  });
});
