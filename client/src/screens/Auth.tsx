import { useState } from 'react';
import { chat } from '../chat/session';
import { ChatError } from '../chat/types';

const MSG: Record<string, string> = {
  'email-taken': 'That email already has an account. Try signing in.',
  'bad-credentials': 'Email or password is incorrect.',
  invalid: 'Enter a valid email, a name, and a password of at least 8 characters.',
  'rate-limited': 'Too many attempts. Please wait a few minutes and try again.',
  network: 'Could not reach the server. Check your connection and try again.',
};

export default function Auth() {
  const [mode, setMode] = useState<'in' | 'up'>('in');
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [pw, setPw] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  async function submit() {
    setErr('');
    setBusy(true);
    try {
      if (mode === 'up') await chat.register(email, pw, name || email.split('@')[0]);
      else await chat.login(email, pw);
    } catch (e) {
      setErr(e instanceof ChatError ? MSG[e.code] ?? 'Something went wrong.' : 'Something went wrong.');
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="card">
      <h1>{mode === 'in' ? 'Sign in to secret chats' : 'Create your account'}</h1>
      <p className="muted">Accounts are only for chats. Sending a one-time link never needs one.</p>
      <input className="field" type="email" autoComplete="email" placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} />
      {mode === 'up' && <input className="field" autoComplete="nickname" placeholder="Display name" maxLength={40} value={name} onChange={(e) => setName(e.target.value)} />}
      <input className="field" type="password" autoComplete={mode === 'in' ? 'current-password' : 'new-password'} placeholder="Password (8+ characters)" value={pw} onChange={(e) => setPw(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && submit()} />
      {err && <p className="banner danger" role="alert">{err}</p>}
      <button className="btn primary block" disabled={busy} onClick={submit}>{busy ? 'Please wait…' : mode === 'in' ? 'Sign in' : 'Create account'}</button>
      <button className="btn ghost" onClick={() => { setMode(mode === 'in' ? 'up' : 'in'); setErr(''); }}>
        {mode === 'in' ? 'New here? Create an account' : 'Have an account? Sign in'}
      </button>
      <p className="banner info">Your device creates a private key that never leaves it. If you sign in on a new device, older chats cannot be read there.</p>
    </section>
  );
}
