import { useState } from 'react';
import { chat, useSession } from '../chat/session';
import { clearSent, loadSettings, saveSettings, type Settings } from '../storage';

export default function SettingsScreen() {
  const [s, setS] = useState<Settings>(loadSettings());
  const [cleared, setCleared] = useState(false);
  const user = useSession();
  const [del, setDel] = useState(false);
  const [delPw, setDelPw] = useState('');
  const [delErr, setDelErr] = useState('');
  async function erase() {
    setDelErr('');
    try { await chat.deleteAccount(delPw); setDel(false); setDelPw(''); }
    catch (e) { setDelErr((e as { code?: string }).code === 'bad-credentials' ? 'That password is not correct.' : 'Could not delete the account. Try again.'); }
  }
  const set = (p: Partial<Settings>) => { const n = { ...s, ...p }; setS(n); saveSettings(n); };
  return (
    <section className="card">
      <h1>Settings</h1>
      <label className="lbl" htmlFor="exp">Default expiry</label>
      <select id="exp" className="field" value={s.expiry} onChange={(e) => set({ expiry: Number(e.target.value) as 3600 | 86400 })}>
        <option value={3600}>1 hour</option>
        <option value={86400}>24 hours</option>
      </select>
      <label className="lbl" htmlFor="hide">Hide a revealed message after</label>
      <select id="hide" className="field" value={s.autoHide} onChange={(e) => set({ autoHide: Number(e.target.value) })}>
        <option value={15}>15 seconds</option>
        <option value={30}>30 seconds</option>
        <option value={60}>60 seconds</option>
      </select>
      <label className="lbl" htmlFor="burn">Chat messages burn after opening</label>
      <select id="burn" className="field" value={s.burn} onChange={(e) => set({ burn: Number(e.target.value) as 15 | 30 | 60 })}>
        <option value={15}>15 seconds</option>
        <option value={30}>30 seconds</option>
        <option value={60}>60 seconds</option>
      </select>
      <label className="lbl" htmlFor="theme">Theme</label>
      <select id="theme" className="field" value={s.theme} onChange={(e) => set({ theme: e.target.value as Settings['theme'] })}>
        <option value="system">Match my device</option>
        <option value="light">Light</option>
        <option value="dark">Dark</option>
      </select>
      {user && <button className="btn secondary" onClick={() => { chat.logout(); }}>Sign out ({user.displayName})</button>}
      {user && !del && <button className="btn ghost" onClick={() => setDel(true)}>Delete my account</button>}
      {user && del && (
        <div className="card">
          <p className="banner danger">This permanently removes your account, your chats and every message in them, for you and the other person. It cannot be undone.</p>
          <input className="field" type="password" autoComplete="current-password" placeholder="Enter your password to confirm" value={delPw} onChange={(e) => setDelPw(e.target.value)} aria-label="Password to confirm deletion" />
          {delErr && <p className="banner danger" role="alert">{delErr}</p>}
          <div className="row">
            <button className="btn primary" onClick={erase}>Permanently delete</button>
            <button className="btn ghost" onClick={() => { setDel(false); setDelErr(''); setDelPw(''); }}>Cancel</button>
          </div>
        </div>
      )}
      <button className="btn secondary" onClick={() => { clearSent(); setCleared(true); }}>Clear sent list on this device</button>
      {cleared && <p className="muted small">Cleared.</p>}
      <p className="banner info">Messages are encrypted in your browser with AES-256-GCM. The server stores only ciphertext and can never read it. The key stays in the part of the link after the # sign, which browsers do not send to servers.</p>
    </section>
  );
}
