import mysql, { type Pool, type PoolConnection, type ResultSetHeader } from 'mysql2/promise';
import type { Db, Row, Tx } from './driver.js';

/** MySQL (or a MySQL-compatible service such as TiDB Cloud). Every query is a prepared statement with bound parameters. */
export function openMysql(url: string, opts: { ssl?: boolean } = {}): Db {
  const pool: Pool = mysql.createPool({
    uri: url,
    connectionLimit: 10,
    waitForConnections: true,
    supportBigNumbers: true,
    bigNumberStrings: false,
    charset: 'utf8mb4',
    ssl: opts.ssl ? { minVersion: 'TLSv1.2', rejectUnauthorized: true } : undefined,
  });
  const q = async (c: Pool | PoolConnection, sql: string, p: unknown[]): Promise<Row[]> => {
    const [r] = await c.execute(sql, p as never[]);
    return r as unknown as Row[];
  };
  const e = async (c: Pool | PoolConnection, sql: string, p: unknown[]): Promise<number> => {
    const [r] = await c.execute(sql, p as never[]);
    return (r as ResultSetHeader).affectedRows;
  };
  return {
    dialect: 'mysql',
    query: (s, p = []) => q(pool, s, p),
    exec: (s, p = []) => e(pool, s, p),
    async transaction<T>(fn: (t: Tx) => Promise<T>) {
      const c = await pool.getConnection();
      try {
        await c.beginTransaction();
        const r = await fn({ query: (s, p = []) => q(c, s, p), exec: (s, p = []) => e(c, s, p) });
        await c.commit();
        return r;
      } catch (err) {
        try { await c.rollback(); } catch { /* connection already gone */ }
        throw err;
      } finally {
        c.release();
      }
    },
    close: () => pool.end(),
  };
}
