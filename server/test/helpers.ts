import { AccountStore } from '../src/accounts';
import { openMysql } from '../src/db/mysql';
import { migrate, resetTables } from '../src/db/schema';
import { openSqlite } from '../src/db/sqlite';
import { SecretStore } from '../src/store';

export type Kind = 'sqlite' | 'mysql';
/** Every test runs on SQLite. When TEST_MYSQL_URL is set it also runs against a real MySQL server. */
export const KINDS: Kind[] = process.env.TEST_MYSQL_URL ? ['sqlite', 'mysql'] : ['sqlite'];

export async function makeStores(kind: Kind) {
  const db = kind === 'sqlite' ? openSqlite(':memory:') : openMysql(process.env.TEST_MYSQL_URL!);
  await migrate(db);
  await resetTables(db);
  return { db, secrets: new SecretStore(db), accounts: new AccountStore(db) };
}
export type Stores = Awaited<ReturnType<typeof makeStores>>;

export const LIMITS = { create: 1e6, reveal: 1e6, status: 1e6, auth: 1e6, lookup: 1e6, send: 1e6 };
