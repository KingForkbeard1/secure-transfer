import type { Db } from './driver.js';

// One schema for both engines. Types are chosen so MySQL and SQLite both accept them.
const TABLES = [
  `CREATE TABLE IF NOT EXISTS secrets (
     id VARCHAR(22) PRIMARY KEY,
     ciphertext LONGBLOB NOT NULL,
     iv BLOB NOT NULL,
     kind VARCHAR(8) NOT NULL,
     salt VARCHAR(64),
     verifier_hash CHAR(64),
     attempts INT NOT NULL DEFAULT 0,
     created_at BIGINT NOT NULL,
     expires_at BIGINT NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS tombstones (
     id VARCHAR(22) PRIMARY KEY,
     status VARCHAR(8) NOT NULL,
     at BIGINT NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS users (
     id CHAR(36) PRIMARY KEY,
     email VARCHAR(254) NOT NULL UNIQUE,
     display_name VARCHAR(40) NOT NULL,
     pw_hash VARCHAR(255) NOT NULL,
     public_key TEXT,
     created_at BIGINT NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS sessions (
     token_hash CHAR(64) PRIMARY KEY,
     user_id CHAR(36) NOT NULL,
     created_at BIGINT NOT NULL,
     expires_at BIGINT NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS chats (
     id CHAR(36) PRIMARY KEY,
     user_a CHAR(36) NOT NULL,
     user_b CHAR(36) NOT NULL,
     created_at BIGINT NOT NULL,
     UNIQUE (user_a, user_b)
   )`,
  `CREATE TABLE IF NOT EXISTS messages (
     id CHAR(36) PRIMARY KEY,
     chat_id CHAR(36) NOT NULL,
     sender_id CHAR(36) NOT NULL,
     ciphertext LONGBLOB,
     iv BLOB,
     burn_seconds INT NOT NULL,
     status VARCHAR(8) NOT NULL,
     created_at BIGINT NOT NULL
   )`,
];
const INDEXES = [
  'CREATE INDEX secrets_expires ON secrets (expires_at)',
  'CREATE INDEX sessions_user ON sessions (user_id)',
  'CREATE INDEX messages_chat ON messages (chat_id, created_at)',
  'CREATE INDEX chats_a ON chats (user_a)',
  'CREATE INDEX chats_b ON chats (user_b)',
];

export async function migrate(db: Db): Promise<void> {
  for (const t of TABLES) await db.exec(t);
  for (const i of INDEXES) {
    try {
      await db.exec(db.dialect === 'sqlite' ? i.replace('CREATE INDEX', 'CREATE INDEX IF NOT EXISTS') : i);
    } catch (e) {
      if (!/duplicate key name|already exists/i.test((e as Error).message)) throw e; // MySQL has no IF NOT EXISTS for indexes
    }
  }
}

/** For tests only. */
export async function resetTables(db: Db): Promise<void> {
  for (const t of ['messages', 'chats', 'sessions', 'users', 'tombstones', 'secrets']) await db.exec(`DELETE FROM ${t}`);
}
