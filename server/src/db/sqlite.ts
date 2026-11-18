import Database from 'better-sqlite3';
import type { Db, Row, Tx } from './driver.js';

const strip = (sql: string) => sql.replace(/\s+FOR UPDATE\b/gi, ''); // SQLite locks the whole database in a transaction instead

/** Local fallback: one file, no setup. All work is serialised, so every transaction is atomic. */
export function openSqlite(file = ':memory:'): Db {
  const raw = new Database(file);
  raw.pragma('journal_mode = WAL');
  raw.pragma('secure_delete = ON'); // overwrite deleted content with zeros

  const rows = (sql: string, p: unknown[]): Row[] => {
    const st = raw.prepare(strip(sql));
    if (st.reader) return st.all(...p) as Row[];
    st.run(...p);
    return [];
  };
  const changes = (sql: string, p: unknown[]) => raw.prepare(strip(sql)).run(...p).changes;

  let chain: Promise<unknown> = Promise.resolve();
  const lock = <T>(fn: () => Promise<T> | T): Promise<T> => {
    const p = chain.then(fn, fn);
    chain = p.catch(() => undefined);
    return p;
  };
  const tx: Tx = { query: async (s, p = []) => rows(s, p), exec: async (s, p = []) => changes(s, p) };

  return {
    dialect: 'sqlite',
    query: (s, p = []) => lock(() => rows(s, p)),
    exec: (s, p = []) => lock(() => changes(s, p)),
    transaction: <T>(fn: (t: Tx) => Promise<T>) =>
      lock(async () => {
        raw.exec('BEGIN IMMEDIATE');
        try {
          const r = await fn(tx);
          raw.exec('COMMIT');
          return r;
        } catch (e) {
          raw.exec('ROLLBACK');
          throw e;
        }
      }),
    close: () => lock(() => { raw.close(); }),
  };
}
