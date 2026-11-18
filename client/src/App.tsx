import type { ReactElement } from 'react';
import { useSession, useUnread } from './chat/session';
import { navigate, usePath } from './router';
import Auth from './screens/Auth';
import Chat from './screens/Chat';
import Chats from './screens/Chats';
import Create from './screens/Create';
import Receive from './screens/Receive';
import Reveal from './screens/Reveal';
import Sent from './screens/Sent';
import SettingsScreen from './screens/Settings';

const SECRET = /^\/s\/([A-Za-z0-9_-]{22})\/?$/;
const CHAT = /^\/chats\/([A-Za-z0-9-]+)\/?$/;
const TABS = [
  { path: '/', label: 'Create', icon: '+' },
  { path: '/receive', label: 'Receive', icon: '↓' },
  { path: '/sent', label: 'Sent', icon: '↗' },
  { path: '/chats', label: 'Chats', icon: '✉' },
  { path: '/settings', label: 'Settings', icon: '⚙' },
];

function Brand() {
  return (
    <header className="brand">
      <span className="flame" aria-hidden="true" />
      <span>Secure transfer</span>
    </header>
  );
}

export default function App() {
  const path = usePath();
  const user = useSession();
  const unread = useUnread(user);
  const secret = SECRET.exec(path);
  if (secret) {
    return <div className="app"><Brand /><main><Reveal key={secret[1]} id={secret[1]} /></main></div>;
  }

  const chatMatch = CHAT.exec(path);
  const gated = (node: (u: NonNullable<typeof user>) => ReactElement) =>
    user === undefined ? <section className="card"><p className="muted">Loading…</p></section> : user === null ? <Auth /> : node(user);

  let screen: ReactElement | null = null;
  if (path === '/') screen = <Create />;
  else if (path === '/receive') screen = <Receive />;
  else if (path === '/sent') screen = <Sent />;
  else if (path === '/settings') screen = <SettingsScreen />;
  else if (path === '/chats') screen = gated((u) => <Chats user={u} />);
  else if (chatMatch) screen = gated((u) => <Chat key={chatMatch[1]} user={u} chatId={chatMatch[1]} />);

  const active = (p: string) => (p === '/chats' ? path === '/chats' || !!chatMatch : path === p);
  return (
    <div className="app has-nav">
      <Brand />
      <main>
        {screen ?? (
          <section className="card">
            <h1>Page not found</h1>
            <button className="btn primary" onClick={() => navigate('/')}>Go to Create</button>
          </section>
        )}
      </main>
      <nav className="nav" aria-label="Main">
        {TABS.map((t) => (
          <a
            key={t.path}
            href={t.path}
            className={active(t.path) ? 'active' : ''}
            onClick={(e) => { e.preventDefault(); navigate(t.path); }}
          >
            <span aria-hidden="true">{t.icon}</span>
            {t.label}
            {t.path === '/chats' && unread > 0 && <b className="unread nav-badge" aria-label={`${unread} unread`}>{unread}</b>}
          </a>
        ))}
      </nav>
    </div>
  );
}
