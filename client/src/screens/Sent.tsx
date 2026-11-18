import { useEffect, useState } from 'react';
import { api } from '../api';
import { clearSent, loadSent, removeSent, type SentItem } from '../storage';

type St = 'waiting' | 'opened' | 'expired';
const LABEL: Record<St, string> = { waiting: 'Waiting', opened: 'Opened', expired: 'Expired' };

function when(i: SentItem, st: St | undefined): string {
  if (st === 'waiting') {
    const h = Math.max(0, i.expiresAt - Date.now()) / 3600_000;
    return h >= 1 ? `Expires in ${Math.round(h)} h` : `Expires in ${Math.max(1, Math.round(h * 60))} min`;
  }
  const mins = Math.round((Date.now() - i.createdAt) / 60000);
  return mins < 60 ? `Sent ${Math.max(mins, 0)} min ago` : mins < 1440 ? `Sent ${Math.round(mins / 60)} h ago` : `Sent ${Math.round(mins / 1440)} d ago`;
}

export default function Sent() {
  const [items, setItems] = useState<SentItem[]>(loadSent());
  const [status, setStatus] = useState<Record<string, St>>({});

  useEffect(() => {
    let live = true;
    const poll = async () => {
      for (const i of loadSent()) {
        if (status[i.id] && status[i.id] !== 'waiting') continue;
        try {
          const r = await api.status(i.id);
          if (!live) return;
          setStatus((s) => ({ ...s, [i.id]: r.status === 404 || r.data.status === 'unknown' ? 'expired' : (r.data.status as St) }));
        } catch { /* offline: keep last known */ }
      }
    };
    poll();
    const t = setInterval(poll, 15000);
    return () => { live = false; clearInterval(t); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <section className="card">
      <h1>Your secrets</h1>
      {items.length === 0 && <p className="muted">Nothing sent yet. Links you create appear here with their status.</p>}
      <ul className="list">
        {items.map((i) => {
          const st = status[i.id];
          return (
            <li key={i.id}>
              <div className="grow">
                <strong>{i.label}</strong>
                <div className="muted small">{when(i, st)}</div>
              </div>
              <span className={`badge ${st ?? 'wait'}`}>{st ? LABEL[st] : '…'}</span>
              <button className="btn ghost small" aria-label={`Remove ${i.label}`} onClick={() => { removeSent(i.id); setItems(loadSent()); }}>✕</button>
            </li>
          );
        })}
      </ul>
      <p className="banner info">Only status is kept, on this device. Message content is never stored. If a link shows Opened and the recipient says they did not open it, treat the secret as compromised.</p>
      {items.length > 0 && <button className="btn ghost" onClick={() => { clearSent(); setItems([]); }}>Clear list</button>}
    </section>
  );
}
