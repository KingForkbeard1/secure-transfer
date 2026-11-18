import { useEffect, useState } from 'react';
import QRCode from 'qrcode';
import {
  MAX_FILE_BYTES, b64urlEncode, deriveAesKey, deriveVerifier, encryptPayload, newLinkKey, newSalt,
  textPayload, type Payload, type Protection,
} from '../crypto';
import { api } from '../api';
import { addSent, loadSettings } from '../storage';
import { navigate } from '../router';

interface Made { url: string; expiresAt: number; passphrase: boolean }

function LinkPanel({ made, onReset }: { made: Made; onReset: () => void }) {
  const [qr, setQr] = useState('');
  const [copied, setCopied] = useState(false);
  useEffect(() => { QRCode.toDataURL(made.url, { margin: 1, width: 240 }).then(setQr).catch(() => {}); }, [made.url]);
  const copy = async () => {
    try { await navigator.clipboard.writeText(made.url); setCopied(true); setTimeout(() => setCopied(false), 2000); } catch { /* user can select manually */ }
  };
  const canShare = typeof navigator.share === 'function';
  return (
    <section className="card">
      <h1>Your one-time link</h1>
      <p className="muted">
        Opens once, then it is destroyed. Unopened, it self-destructs on {new Date(made.expiresAt).toLocaleString()}.
      </p>
      <input className="field mono" readOnly value={made.url} onFocus={(e) => e.currentTarget.select()} aria-label="One-time link" />
      <div className="row">
        <button className="btn primary" onClick={copy}>{copied ? 'Copied' : 'Copy link'}</button>
        {canShare && (
          <button className="btn secondary" onClick={() => navigator.share({ title: 'Secure transfer', url: made.url }).catch(() => {})}>Share</button>
        )}
      </div>
      <button className="btn ghost" onClick={() => navigate(new URL(made.url).pathname + new URL(made.url).hash)}>Open it now (this uses up the link)</button>
      {qr && <img className="qr" src={qr} alt="QR code for the link" width={160} height={160} />}
      {made.passphrase && (
        <p className="banner warn">Send the passphrase through a different channel, such as a call or in person. Never in the same message as the link.</p>
      )}
      <button className="btn ghost" onClick={onReset}>Create another</button>
    </section>
  );
}

export default function Create() {
  const settings = loadSettings();
  const [mode, setMode] = useState<'text' | 'file'>('text');
  const [text, setText] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [label, setLabel] = useState('');
  const [ttl, setTtl] = useState<3600 | 86400>(settings.expiry);
  const [usePass, setUsePass] = useState(false);
  const [pass, setPass] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [made, setMade] = useState<Made | null>(null);

  const reset = () => { setMade(null); setText(''); setFile(null); setLabel(''); setPass(''); setUsePass(false); setError(''); };

  async function submit() {
    setError('');
    if (mode === 'text' && !text.trim()) return setError('Type or paste something to send.');
    if (mode === 'file' && !file) return setError('Choose a file to send.');
    if (mode === 'file' && file!.size > MAX_FILE_BYTES) return setError('That file is over the 5 MB limit.');
    if (mode === 'file' && file!.size === 0) return setError('That file is empty.');
    if (usePass && pass.length < 8) return setError('Use a passphrase of at least 8 characters.');
    setBusy(true);
    try {
      const linkKey = newLinkKey();
      let prot: Protection | undefined;
      let verifier: string | undefined;
      if (usePass) {
        prot = { pass, salt: newSalt() };
        verifier = await deriveVerifier(prot);
      }
      const key = await deriveAesKey(linkKey, prot);
      const payload: Payload =
        mode === 'text'
          ? textPayload(text)
          : { kind: 'file', name: file!.name.slice(0, 200), mime: file!.type || 'application/octet-stream', data: new Uint8Array(await file!.arrayBuffer()) };
      const enc = await encryptPayload(key, payload);
      const res = await api.create({ ...enc, kind: payload.kind, ttl, ...(prot ? { salt: prot.salt, verifier } : {}) });
      if (res.status === 429) return setError('Too many links created from this connection. Please try again later.');
      if (res.status !== 201) return setError('The server rejected the request. Check the size and try again.');
      const url = `${location.origin}/s/${res.data.id}#${b64urlEncode(linkKey)}`;
      addSent({
        id: res.data.id,
        label: label.trim().slice(0, 40) || (mode === 'file' ? 'File' : 'Text secret'),
        kind: payload.kind,
        createdAt: Date.now(),
        expiresAt: res.data.expiresAt,
      });
      setMade({ url, expiresAt: res.data.expiresAt, passphrase: usePass });
      setText(''); setPass(''); setFile(null);
    } catch {
      setError('Something went wrong while encrypting or sending. Nothing was stored.');
    } finally {
      setBusy(false);
    }
  }

  if (made) return <LinkPanel made={made} onReset={reset} />;
  return (
    <section className="card">
      <h1>New secret</h1>
      <p className="muted">Encrypted in your browser before it leaves your device.</p>
      <div className="seg" role="tablist">
        <button role="tab" aria-selected={mode === 'text'} className={mode === 'text' ? 'on' : ''} onClick={() => setMode('text')}>Text</button>
        <button role="tab" aria-selected={mode === 'file'} className={mode === 'file' ? 'on' : ''} onClick={() => setMode('file')}>File</button>
      </div>
      {mode === 'text' ? (
        <textarea className="field" rows={5} maxLength={200000} placeholder="Paste a password, API key, or note" value={text} onChange={(e) => setText(e.target.value)} />
      ) : (
        <label className="drop">
          <input type="file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
          <span>{file ? `${file.name} (${(file.size / 1024).toFixed(0)} KB)` : 'Choose a file (up to 5 MB)'}</span>
        </label>
      )}
      <label className="lbl">Label (optional, stays on this device)</label>
      <input className="field" maxLength={40} value={label} onChange={(e) => setLabel(e.target.value)} placeholder="e.g. Database login" />
      <label className="lbl">Self-destructs after</label>
      <div className="chips">
        <button className={`chip ${ttl === 3600 ? 'on' : ''}`} onClick={() => setTtl(3600)}>1 hour</button>
        <button className={`chip ${ttl === 86400 ? 'on' : ''}`} onClick={() => setTtl(86400)}>24 hours</button>
      </div>
      <label className="switch">
        <input type="checkbox" checked={usePass} onChange={(e) => setUsePass(e.target.checked)} />
        <span>Add passphrase</span>
      </label>
      {usePass && (
        <input className="field" type="password" autoComplete="new-password" placeholder="At least 8 characters" value={pass} onChange={(e) => setPass(e.target.value)} />
      )}
      {error && <p className="banner danger" role="alert">{error}</p>}
      <button className="btn primary block" disabled={busy} onClick={submit}>{busy ? 'Encrypting…' : 'Create secure link'}</button>
    </section>
  );
}
