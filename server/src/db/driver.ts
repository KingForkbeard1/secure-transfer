export type Row = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
export interface Tx {
  query(sql: string, params?: unknown[]): Promise<Row[]>;
  /** Returns the number of affected rows. */
  exec(sql: string, params?: unknown[]): Promise<number>;
}
/** The only thing the stores know about the database. MySQL and SQLite each implement it. */
export interface Db extends Tx {
  dialect: 'sqlite' | 'mysql';
  /** Inside the callback use only the `tx` argument. Rows read with FOR UPDATE stay locked until it finishes. */
  transaction<T>(fn: (tx: Tx) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}
