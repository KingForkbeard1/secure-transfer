import cron from 'node-cron';
import type { AccountStore } from './accounts.js';
import type { SecretStore } from './store.js';

/** Fail-safe sweep every 5 minutes: destroys expired secrets, week-old unread messages and expired sessions. */
export function startSweeper(secrets: SecretStore, accounts: AccountStore) {
  const run = async () => {
    try {
      const now = Date.now();
      const n = await secrets.sweep(now);
      const m = await accounts.expireMessages(now);
      await accounts.sweepSessions(now);
      if (n + m > 0) console.log(`[sweeper] destroyed ${n} secret(s) and ${m} unread message(s)`);
    } catch (e) {
      console.error('[sweeper] failed', (e as Error).message);
    }
  };
  void run();
  return cron.schedule('*/5 * * * *', () => { void run(); });
}
