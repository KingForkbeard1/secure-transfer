// Device-only storage. Holds status metadata, never message content, keys, or passphrases.
export interface SentItem { id: string; label: string; kind: 'text' | 'file'; createdAt: number; expiresAt: number }
export interface Settings { expiry: 3600 | 86400; autoHide: number; burn: 15 | 30 | 60; theme: 'system' | 'light' | 'dark' }

const SENT = 'st.sent';
const SET = 'st.settings';
const defaults: Settings = { expiry: 86400, autoHide: 30, burn: 30, theme: 'system' };

export function loadSent(): SentItem[] {
  try {
    const v = JSON.parse(localStorage.getItem(SENT) ?? '[]');
    return Array.isArray(v) ? (v as SentItem[]) : [];
  } catch { return []; }
}
function saveSent(list: SentItem[]) {
  try { localStorage.setItem(SENT, JSON.stringify(list.slice(0, 100))); } catch { /* storage unavailable */ }
}
export const addSent = (i: SentItem) => saveSent([i, ...loadSent()]);
export const removeSent = (id: string) => saveSent(loadSent().filter((x) => x.id !== id));
export const clearSent = () => saveSent([]);

export function loadSettings(): Settings {
  try { return { ...defaults, ...JSON.parse(localStorage.getItem(SET) ?? '{}') }; } catch { return defaults; }
}
export function saveSettings(s: Settings) {
  try { localStorage.setItem(SET, JSON.stringify(s)); } catch { /* storage unavailable */ }
  applyTheme(s.theme);
}
export function applyTheme(t: Settings['theme']) {
  if (t === 'system') delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = t;
}
