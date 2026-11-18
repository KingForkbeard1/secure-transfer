export interface DeviceKeys { privateKey: CryptoKey; publicJwk: JsonWebKey }
export interface KeyStore {
  get(userId: string): Promise<DeviceKeys | null>;
  put(userId: string, keys: DeviceKeys): Promise<void>;
}

export function memoryKeyStore(): KeyStore {
  const m = new Map<string, DeviceKeys>();
  return { get: async (id) => m.get(id) ?? null, put: async (id, k) => void m.set(id, k) };
}

/** Private keys live in IndexedDB as non-extractable CryptoKey objects: scripts can use them but never read them. */
export function idbKeyStore(): KeyStore {
  const open = () =>
    new Promise<IDBDatabase>((res, rej) => {
      const r = indexedDB.open('secure-transfer-keys', 1);
      r.onupgradeneeded = () => r.result.createObjectStore('keys');
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    });
  const tx = async <T,>(mode: IDBTransactionMode, f: (s: IDBObjectStore) => IDBRequest<T>) => {
    const db = await open();
    return new Promise<T>((res, rej) => {
      const r = f(db.transaction('keys', mode).objectStore('keys'));
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    });
  };
  return {
    get: async (id) => ((await tx('readonly', (s) => s.get(id))) as DeviceKeys | undefined) ?? null,
    put: async (id, k) => void (await tx('readwrite', (s) => s.put(k, id))),
  };
}
