# Secure Transfer (Phase 1 + Phase 2)

Burn-after-reading transfer, built in two phases:

- **Phase 1, one-time links:** encrypt text or a file (up to 5 MB) in your browser, share a link, it opens once and is destroyed. No account needed.
- **Phase 2, secret chats:** accounts, search by exact email, and one-to-one chats whose messages are end-to-end encrypted and burn after reading.

Everything is encrypted on the device. The server stores only ciphertext, public keys and metadata.

## Run it (Windows, Mac, Linux)

Requirements: **Node.js 22.14 or newer** (nodejs.org, LTS). Keep the folder **outside OneDrive**.

```
npm install
npm run dev        # development: http://localhost:5173
npm start          # builds, then serves everything at http://localhost:3000
```

With no setup it keeps data in a local SQLite file (`server/data/secrets.db`), so links and chats work on your own computer. To use MySQL, set `DATABASE_URL` (see below). `npm test` runs the checks, `npm run typecheck` checks types.

The `.npmrc` turns off install scripts on purpose, because the SQLite package ships ready-made binaries. If `npm install` ever asks for Visual Studio or Python, check that `.npmrc` is present.

## Try the chats on one computer
Open the Chats tab, create an account, then open a second browser window (or a private window) and create a second account. Start a chat using the first account's email. Messages arrive live.

## Database: MySQL for everything

| Setting | Meaning |
|---|---|
| `DATABASE_URL` | `mysql://user:password@host:3306/dbname`. When set, links, accounts, chats and messages all live in MySQL |
| `DATABASE_SSL=1` | Needed by most hosted MySQL services (encrypted connection) |
| (neither set) | Local SQLite file, for development |

Tables are created automatically on start. A MySQL-compatible service such as TiDB Cloud works too. Check its row-size limit: a 5 MB file is stored as one row of about 5 MB. Never put the connection string in the repository; set it in your host's environment settings.

All database code sits behind one small interface (`server/src/db/`), so the same queries run on MySQL and SQLite.

## How it works

**Links.** The browser makes a random 256-bit key, encrypts with AES-256-GCM (Web Crypto API), and sends only ciphertext. The key stays in the part of the link after `#`, which browsers never send. The recipient opens a landing page; only the **Reveal** button (a POST) destroys the record, so chat-app link previews cannot burn it. The server locks the row, returns it and deletes it in one transaction, so two simultaneous reveals can never both succeed. An optional passphrase is mixed into the key (PBKDF2, 600,000 rounds); five wrong attempts destroy the secret. A sweeper deletes unopened secrets after 1 or 24 hours. Use the **Receive** tab to paste a link.

**Chats.** Each device makes an ECDH P-256 key pair; the private key is non-extractable and kept in IndexedDB. The conversation key is derived on both devices (ECDH + HKDF) and never leaves them. Messages are AES-256-GCM encrypted before sending. The recipient taps to reveal; the server returns the ciphertext and destroys it in one locked transaction, so it is gone for both people and the message hides after your burn timer. A safety number (six groups of five digits) is the same for both people; compare it on a call to detect interception.

**Accounts.** scrypt password hashes, `httpOnly` `SameSite=Strict` session cookies (only a hash of the token is stored), same-origin checks on every state-changing request, rate limits, and an account-deletion button that erases the account, chats and messages.

## Tests

`npm test` runs 66 tests on SQLite. To also run the server tests against a real MySQL server (103 tests in all):

```
TEST_MYSQL_URL="mysql://user:password@127.0.0.1:3306/testdb" npm test -w server
```
(on Windows PowerShell: `$env:TEST_MYSQL_URL="mysql://..."; npm test -w server`). The test database is emptied on each run, so use a throwaway one.

Covered: encryption (round trips, tampering, wrong keys, passphrases), burn-once under 20 simultaneous requests, expiry and sweeping, passphrase attempt limits, sessions and cookies, CSRF blocking, rate limits, exact-email search, outsiders blocked from chats, 7-day message expiry, live-update stream, account erasure, and the front-end chat code talking to the real server for two people. All of it also ran against MySQL 8.

Not yet done: OWASP ZAP scan, a real-browser end-to-end run, Lighthouse, a real-phone install test, latency measurements, and user testing. Collect those as evidence for your report.

## Deploy on Render

1. Put the project on GitHub (`.gitignore` already skips `node_modules`, `dist`, databases).
2. Create a hosted MySQL database and copy its connection string.
3. On render.com choose **New > Blueprint** and pick the repository (it reads `render.yaml`), or create a Web Service by hand: build `npm install --include=dev && npm run build`, start `npm run start -w server`, health check `/api/health`.
4. In the service's **Environment** tab set `DATABASE_URL` (your connection string), `DATABASE_SSL=1`, `TRUST_PROXY=1`, and `NODE_VERSION=22.20.0`.
5. Open the `onrender.com` address (HTTPS, so encryption works on phones).

Without `DATABASE_URL` a free Render service keeps data in a file that is wiped when it sleeps, so everything vanishes. With MySQL it survives. The free plan still sleeps after 15 idle minutes, so the first load takes about a minute. Node 22.12 and 22.13 crash with the SQLite package, which is why the app refuses to start on versions below 22.14.

## Known limitations (state these in your threat model)
- Someone who gets a link first can open it. The design makes this visible (the sender sees Opened, the recipient sees "Nothing here") and a passphrase makes a stolen link useless, but it cannot be prevented.
- Chats have no forward secrecy, and a new device cannot read old chats.
- The server sees who talks to whom, when, message sizes and IP addresses. Accounts mean storing emails and password hashes, so Kenya's Data Protection Act applies (privacy notice and a data-protection registration decision are still to do).
- A compromised device, a screenshot, or a shoulder-surfer defeats any web app.
- A managed MySQL service cannot promise physical erasure of deleted rows. The guarantee rests on the key never being stored (cryptographic erasure).

## Layout
```
client/   React + Vite PWA (src/crypto = all encryption, src/chat = chat services, src/screens = UI)
server/   Express API (src/db = MySQL and SQLite drivers, src/store.ts = links, src/accounts.ts = chats)
docs/     docs/PHASE2_API_CONTRACT.md
```
