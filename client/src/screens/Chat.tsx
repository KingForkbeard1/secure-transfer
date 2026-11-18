import { useCallback, useEffect, useRef, useState } from 'react';
import { chat, keyStore } from '../chat/session';
import type { ChatSummary, Message, User } from '../chat/types';
import { decryptPayload, encryptPayload, payloadText, textPayload } from '../crypto';
import { deriveConversationKey, safetyNumber } from '../crypto/chat';
import { navigate } from '../router';
import { loadSettings } from '../storage';

interface Open { text: string; left: number }

export default function Chat({ user, chatId }: { user: User; chatId: string }) {
  const [info, setInfo] = useState<ChatSummary | null>(null);
  const [msgs, setMsgs] = useState<Message[]>([]);
  const [key, setKey] = useState<CryptoKey | null>(null);
  const [safety, setSafety] = useState('');
  const [showSafety, setShowSafety] = useState(false);
  const [own, setOwn] = useState<Record<string, string>>({});
  const [open, setOpen] = useState<Record<string, Open>>({});
  const [text, setText] = useState('');
  const [err, setErr] = useState('');
  const [missing, setMissing] = useState(false);
  const decrypting = useRef(new Set<string>());

  useEffect(() => {
    let live = true;
    (async () => {
      try {
        const c = await chat.getChat(chatId);
        const mine = await keyStore.get(user.id);
        if (!live) return;
        setInfo(c);
        if (mine) {
          setKey(await deriveConversationKey(mine.privateKey, c.peer.publicKey));
          setSafety(await safetyNumber(mine.publicJwk, c.peer.publicKey));
        }
      } catch { if (live) setMissing(true); }
    })();
    return () => { live = false; };
  }, [chatId, user.id]);

  const load = useCallback(() => chat.messages(chatId).then(setMsgs).catch(() => setMissing(true)), [chatId]);
  useEffect(() => {
    load();
    return chat.subscribe(load);
  }, [load]);

  // The sender can read their own messages until the other person opens them.
  useEffect(() => {
    if (!key) return;
    for (const m of msgs) {
      if (m.fromMe && m.status === 'sent' && m.ciphertext && !own[m.id] && !decrypting.current.has(m.id)) {
        decrypting.current.add(m.id);
        decryptPayload(key, m.ciphertext, m.iv!).then((p) => setOwn((o) => ({ ...o, [m.id]: payloadText(p) }))).catch(() => {});
      }
    }
  }, [msgs, key, own]);

  // Burn countdown for messages that have been revealed on this screen.
  useEffect(() => {
    const t = setInterval(() => {
      setOpen((o) => {
        const next: Record<string, Open> = {};
        for (const [id, v] of Object.entries(o)) if (v.left > 1) next[id] = { ...v, left: v.left - 1 };
        return next;
      });
    }, 1000);
    return () => clearInterval(t);
  }, []);

  async function reveal(m: Message) {
    if (!key) return;
    setErr('');
    const r = await chat.reveal(m.id);
    if (!r) { load(); return; }
    try {
      const p = await decryptPayload(key, r.ciphertext, r.iv);
      setOpen((o) => ({ ...o, [m.id]: { text: payloadText(p), left: m.burnSeconds } }));
    } catch {
      setOpen((o) => ({ ...o, [m.id]: { text: 'This message could not be decrypted. It may have been sent to a different device or key.', left: 10 } }));
    }
  }

  async function send() {
    const t = text.trim();
    if (!t || !key) return;
    setErr('');
    try {
      const enc = await encryptPayload(key, textPayload(t));
      await chat.send(chatId, enc.ciphertext, enc.iv, loadSettings().burn);
      setText('');
      load();
    } catch { setErr('Could not send. Try again.'); }
  }

  if (missing) return <section className="card"><h1>Chat not found</h1><button className="btn primary" onClick={() => navigate('/chats')}>Back to chats</button></section>;
  return (
    <section className="card">
      <div className="row nowrap center">
        <button className="btn ghost fixed" aria-label="Back to chats" onClick={() => navigate('/chats')}>←</button>
        <div className="grow">
          <strong>{info?.peer.displayName ?? '…'}</strong>
          <div className="muted small">Encrypted on both devices</div>
        </div>
        <button className="btn ghost fixed small" onClick={() => setShowSafety((s) => !s)}>{showSafety ? 'Hide' : 'Verify'}</button>
      </div>
      {showSafety && (
        <p className="banner info">
          Safety number: <strong className="mono">{safety || '…'}</strong>
          <span className="block small">Compare this with {info?.peer.displayName} in person or on a call. If it matches, nobody is intercepting your chat.</span>
        </p>
      )}
      <div className="msgs" aria-live="polite">
        {msgs.length === 0 && <p className="muted small">No messages yet. Say something secret.</p>}
        {msgs.map((m) => {
          if (m.fromMe) {
            return m.status === 'burned'
              ? <div key={m.id} className="bubble them burned">Message burned</div>
              : <div key={m.id} className="bubble me">{own[m.id] ?? '…'}<div className="small faint">Not opened yet</div></div>;
          }
          const o = open[m.id];
          if (o) return <div key={m.id} className="bubble them">{o.text}<div className="small faint">Burns in {o.left} s</div></div>;
          if (m.status === 'burned') return <div key={m.id} className="bubble them burned">Message burned</div>;
          return (
            <button key={m.id} className="bubble them reveal" onClick={() => reveal(m)}>
              Tap to reveal
              <span className="small block">Burns {m.burnSeconds} s after opening</span>
            </button>
          );
        })}
      </div>
      {err && <p className="banner danger" role="alert">{err}</p>}
      <div className="row nowrap">
        <input className="field" placeholder="Write a secret message" value={text} onChange={(e) => setText(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && send()} aria-label="Message" />
        <button className="btn primary fixed" disabled={!key} onClick={send}>Send</button>
      </div>
    </section>
  );
}
