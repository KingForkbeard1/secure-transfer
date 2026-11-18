import { useEffect, useState } from 'react';
import { chat } from '../chat/session';
import type { ChatSummary, User } from '../chat/types';
import { navigate } from '../router';

const initials = (n: string) => n.split(/\s+/).map((w) => w[0]).join('').slice(0, 2).toUpperCase();

function preview(c: ChatSummary): string {
  if (!c.last) return 'No messages yet';
  if (c.unread > 0) return 'Tap to reveal';
  if (c.last.status === 'burned') return 'Message burned';
  return c.last.fromMe ? 'Waiting to be opened' : 'Tap to reveal';
}

export default function Chats({ user }: { user: User }) {
  const [chats, setChats] = useState<ChatSummary[]>([]);
  const [email, setEmail] = useState('');
  const [err, setErr] = useState('');

  useEffect(() => {
    let live = true;
    const load = () => chat.listChats().then((c) => live && setChats([...c].sort((a, b) => (b.last?.at ?? 0) - (a.last?.at ?? 0)))).catch(() => {});
    load();
    const off = chat.subscribe(load);
    return () => { live = false; off(); };
  }, []);

  async function start() {
    setErr('');
    if (!email.trim()) return;
    try {
      const peer = await chat.lookup(email);
      if (!peer) return setErr('No one with that email has set up secret chats yet.');
      const c = await chat.openChat(peer.id);
      setEmail('');
      navigate(`/chats/${c.id}`);
    } catch (e) {
      const code = (e as { code?: string }).code;
      setErr(code === 'rate-limited' ? 'Too many searches. Wait a few minutes and try again.' : 'Could not start the chat. Try again.');
    }
  }

  return (
    <section className="card">
      <h1>Secret chats</h1>
      <p className="muted">Signed in as {user.displayName}</p>
      <div className="row nowrap">
        <input className="field" type="email" placeholder="Start a chat: enter their email" value={email} onChange={(e) => setEmail(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && start()} aria-label="Email of the person to chat with" />
        <button className="btn primary fixed" onClick={start}>Start</button>
      </div>
      {err && <p className="banner danger" role="alert">{err}</p>}
      {chats.length === 0 && <p className="muted">No chats yet. Enter a friend’s email above. They need an account first.</p>}
      <ul className="list">
        {chats.map((c) => (
          <li key={c.id}>
            <button className="chatrow" onClick={() => navigate(`/chats/${c.id}`)}>
              <span className="avatar" aria-hidden="true">{initials(c.peer.displayName)}</span>
              <span className="grow">
                <strong>{c.peer.displayName}</strong>
                <span className="muted small block">{preview(c)}</span>
              </span>
              {c.unread > 0 && <span className="unread">{c.unread}</span>}
            </button>
          </li>
        ))}
      </ul>
      <p className="banner info">Messages are encrypted on your device. The server relays ciphertext it cannot read, and each message burns after it is read.</p>
    </section>
  );
}
