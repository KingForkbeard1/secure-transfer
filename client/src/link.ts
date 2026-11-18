/** Finds a Secure Transfer link inside whatever the person pasted (full URL, relative path, or a chat message containing one). */
export function parseLink(input: string): { id: string; key: string } | null {
  const m = /\/s\/([A-Za-z0-9_-]{22})#([A-Za-z0-9_-]{43})(?![A-Za-z0-9_-])/.exec(input.trim());
  return m ? { id: m[1], key: m[2] } : null;
}
