export interface ApiResult<T> { status: number; data: T }

async function call<T>(url: string, init?: RequestInit): Promise<ApiResult<T>> {
  const res = await fetch(url, init);
  let data = {} as T;
  try { data = (await res.json()) as T; } catch { /* empty body */ }
  return { status: res.status, data };
}
const json = (body: unknown): RequestInit => ({
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
});

export interface CreateBody {
  ciphertext: string; iv: string; kind: 'text' | 'file'; ttl: 3600 | 86400; salt?: string; verifier?: string;
}
export const api = {
  create: (b: CreateBody) => call<{ id: string; expiresAt: number }>('/api/secrets', json(b)),
  meta: (id: string) => call<{ kind: 'text' | 'file'; passphraseRequired: boolean; salt: string | null }>(`/api/secrets/${id}`),
  reveal: (id: string, verifier?: string) =>
    call<{ ciphertext: string; iv: string; kind: 'text' | 'file'; attemptsLeft?: number }>(
      `/api/secrets/${id}/reveal`, json(verifier ? { verifier } : {}),
    ),
  status: (id: string) => call<{ status: 'waiting' | 'opened' | 'expired' | 'unknown' }>(`/api/secrets/${id}/status`),
};
