import { useEffect, useRef, useState } from 'react';
import { b64urlDecode, deriveAesKey, decryptPayload, deriveVerifier, payloadText, type Payload, type Protection } from '../crypto';
import { api } from '../api';
import { loadSettings } from '../storage';

type View = 'loading' | 'gone' | 'badlink' | 'landing' | 'revealing' | 'shown' | 'hidden' | 'failed';

export default function Reveal({ id }: { id: string }) {
  const linkKey = useRef<Uint8Array | null>(null);
  const [view, setView] = useState<View>('loading');
  const [meta, setMeta] = useState<{ passphraseRequired: boolean; salt: string | null; kind: 'text' | 'file' } | null>(null);
  const [pass, setPass] = useState('');
  const [error, setError] = useState('');
  const [payload, setPayload] = useState<Payload | null>(null);
  const [left, setLeft] = useState(0);

  useEffect(() => {
    try {
      const k = b64urlDecode(location.hash.slice(1));
      linkKey.current = k.length === 32 ? k : null;
    } catch { linkKey.current = null; }
    api.meta(id).then((r) => {
      if (r.status !== 200) return setView('gone');
      setMeta(r.data);
      setView(linkKey.current ? 'landing' : 'badlink');
    }).catch(() => { setError('Could not reach the server.'); setView('failed'); });
  }, [id]);

  useEffect(() => {
    if (view !== 'shown') return;
    const t = setInterval(() => setLeft((n) => n - 1), 1000);
    return () => clearInterval(t);
  }, [view]);
  useEffect(() => {
    if (view === 'shown' && left <= 0) { setPayload(null); setView('hidden'); }
  }, [left, view]);

  async function reveal() {
    if (!meta || !linkKey.current) return;
    setError('');
    if (meta.passphraseRequired && !pass) return setError('Enter the passphrase you were given.');
    setView('revealing');
    try {
      const prot: Protection | undefined = meta.passphraseRequired ? { pass, salt: meta.salt! } : undefined;
      const verifier = prot ? await deriveVerifier(prot) : undefined;
      const res = await api.reveal(id, verifier);
      if (res.status === 401) {
        const n = res.data.attemptsLeft ?? 0;
        if (n <= 0) { setView('gone'); return; }
        setError(`Wrong passphrase. ${n} attempt${n === 1 ? '' : 's'} left before it is destroyed.`);
        setView('landing');
        return;
      }
      if (res.status === 429) { setError('Too many attempts. Wait a while and try again.'); setView('landing'); return; }
      if (res.status !== 200) { setView('gone'); return; }
      history.replaceState(null, '', location.pathname); // drop the key from the address bar
      try {
        const key = await deriveAesKey(linkKey.current, prot);
        setPayload(await decryptPayload(key, res.data.ciphertext, res.data.iv));
        setLeft(loadSettings().autoHide);
        setView('shown');
      } catch {
        setError('The message was destroyed but could not be decrypted. The link may have been damaged or altered. Ask the sender to send a new one.');
        setView('failed');
      }
    } catch {
      setError('Could not reach the server.');
      setView('landing');
    }
  }

  function download() {
    if (!payload) return;
    const url = URL.createObjectURL(new Blob([payload.data as BlobPart], { type: 'application/octet-stream' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = (payload.name ?? 'secret.bin').replace(/[\\/:*?"<>|]/g, '_');
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  if (view === 'loading') return <section className="card"><p className="muted">Checking link…</p></section>;
  if (view === 'gone') return (
    <section className="card">
      <h1>Nothing here</h1>
      <p className="banner danger">This message was already opened, has expired, or never existed. If you did not open it yourself, tell the sender: someone else may have.</p>
    </section>
  );
  if (view === 'badlink') return (
    <section className="card">
      <h1>Incomplete link</h1>
      <p className="banner warn">The part of the link after the # is missing, so the message cannot be unlocked. Ask the sender to share the full link again. Nothing was opened or destroyed.</p>
    </section>
  );
  if (view === 'failed') return <section className="card"><h1>Could not open</h1><p className="banner danger" role="alert">{error}</p></section>;
  if (view === 'hidden') return (
    <section className="card">
      <h1>Hidden</h1>
      <p className="banner danger">The message was destroyed and can no longer be shown. This link no longer works.</p>
    </section>
  );
  if (view === 'shown' && payload) return (
    <section className="card">
      <h1>{payload.kind === 'file' ? 'Your file' : 'Your message'}</h1>
      {payload.kind === 'text' ? (
        <pre className="secret">{payloadText(payload)}</pre>
      ) : (
        <div className="secret"><strong>{payload.name}</strong> <span className="muted">({(payload.data.length / 1024).toFixed(0)} KB)</span>
          <div className="row"><button className="btn primary" onClick={download}>Download file</button></div></div>
      )}
      <p className="banner danger">Destroyed on the server. Copy what you need now. This view hides in {Math.max(left, 0)}s.</p>
      {payload.kind === 'text' && (
        <button className="btn secondary" onClick={() => navigator.clipboard.writeText(payloadText(payload)).catch(() => {})}>Copy text</button>
      )}
    </section>
  );
  return (
    <section className="card">
      <h1>You’ve received a secret</h1>
      <p className="muted">It can be opened once. After you reveal it, it is permanently destroyed.</p>
      {meta?.passphraseRequired && (
        <input className="field" type="password" autoComplete="off" placeholder="Passphrase from the sender" value={pass} onChange={(e) => setPass(e.target.value)} />
      )}
      {error && <p className="banner danger" role="alert">{error}</p>}
      <button className="btn primary block" disabled={view === 'revealing'} onClick={reveal}>
        {view === 'revealing' ? 'Opening…' : 'Reveal message'}
      </button>
    </section>
  );
}
