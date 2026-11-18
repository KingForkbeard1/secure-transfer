import { useState } from 'react';
import { parseLink } from '../link';
import { navigate } from '../router';

export default function Receive() {
  const [text, setText] = useState('');
  const [err, setErr] = useState('');

  function open(value = text) {
    const p = parseLink(value);
    if (!p) return setErr('That does not look like a Secure Transfer link. Paste the whole link, including the part after the # sign.');
    setErr('');
    navigate(`/s/${p.id}#${p.key}`);
  }
  async function paste() {
    try {
      const v = await navigator.clipboard.readText();
      setText(v);
      if (parseLink(v)) open(v);
    } catch {
      setErr('Your browser blocked clipboard access. Paste the link into the box instead.');
    }
  }

  return (
    <section className="card">
      <h1>Receive a secret</h1>
      <p className="muted">Got a one-time link? Paste it here to open it. Opening a link uses it up, so open it only when you are ready to read it.</p>
      <textarea className="field mono" rows={3} placeholder="Paste the link here" value={text} onChange={(e) => setText(e.target.value)} aria-label="One-time link" />
      {err && <p className="banner danger" role="alert">{err}</p>}
      <div className="row">
        <button className="btn primary" onClick={() => open()}>Open link</button>
        <button className="btn secondary" onClick={paste}>Paste from clipboard</button>
      </div>
      <p className="banner info">When someone sends you a link, you can also just tap it. This page is for links you copied by hand.</p>
    </section>
  );
}
