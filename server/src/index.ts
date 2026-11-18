import './preflight.js';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { AccountStore } from './accounts.js';
import { createApp } from './app.js';
import { openMysql } from './db/mysql.js';
import { migrate } from './db/schema.js';
import { openSqlite } from './db/sqlite.js';
import { SecretStore } from './store.js';
import { startSweeper } from './sweeper.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const url = process.env.DATABASE_URL;

let db;
if (url) {
  db = openMysql(url, { ssl: process.env.DATABASE_SSL === '1' });
  console.log('Database: MySQL');
} else {
  const file = process.env.DB_FILE ?? path.resolve(here, '../data/secrets.db');
  mkdirSync(path.dirname(file), { recursive: true });
  db = openSqlite(file);
  console.log(`Database: local SQLite file (${file}). Set DATABASE_URL to use MySQL.`);
}
await migrate(db);

const secrets = new SecretStore(db);
const accounts = new AccountStore(db);
startSweeper(secrets, accounts);

const app = createApp({
  secrets,
  accounts,
  clientDir: path.resolve(here, '../../client/dist'),
  trustProxy: process.env.TRUST_PROXY === '1',
  secureCookie: process.env.NODE_ENV === 'production',
});
const port = Number(process.env.PORT ?? 3000);
app.listen(port, () => console.log(`Secure Transfer listening on http://localhost:${port}`));
