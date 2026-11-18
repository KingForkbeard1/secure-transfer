# Phase 2 API (implemented)

The front end talks to chat only through the `ChatService` interface (`client/src/chat/types.ts`).
`client/src/chat/remote.ts` implements it against the endpoints below. `client/src/chat/mock.ts` is a browser-only version kept for the UI tests (`VITE_CHAT_BACKEND=mock`).

## What the server stores
Email, display name, a scrypt password hash, **public** keys, session-token hashes, and per message: sender, chat, ciphertext, IV, burn seconds, status, timestamp. Never plaintext, never private keys, never message keys. Reveal destroys the ciphertext.

## Sessions and CSRF
Opaque 256-bit session token in an `httpOnly`, `SameSite=Strict`, `Secure` (in production) cookie. Only its SHA-256 hash is stored, expiring after 30 days. Every state-changing request is also checked: if an `Origin` header is present it must match the host. Passwords use scrypt (N=32768, r=8, p=1), stored as `scrypt$N$salt$hash`.

## REST (JSON)

| Purpose | Request | Result |
|---|---|---|
| Register | `POST /api/auth/register {email, password, displayName}` | 201 user + cookie; 409 `email-taken`; 400 `invalid` |
| Sign in | `POST /api/auth/login {email, password}` | 200 user + cookie; 401 `bad-credentials` (same for unknown emails) |
| Sign out | `POST /api/auth/logout` | 204 |
| Who am I | `GET /api/me` | 200 user or 401 |
| Publish key | `PUT /api/me/key {jwk}` | 204. EC P-256, only `kty, crv, x, y`; a `d` field is rejected |
| Delete account | `DELETE /api/me {password}` | 204. Removes sessions, chats and messages |
| Find a person | `GET /api/users/lookup?email=` | Exact email only; 200 or 404. Never a list |
| Open chat | `POST /api/chats {peerId}` | 200 summary (one chat per pair) |
| My chats | `GET /api/chats`, `GET /api/chats/:id` | summaries with `unread` and `last` |
| Messages | `GET /api/chats/:id/messages` | burned messages carry no ciphertext |
| Send | `POST /api/chats/:id/messages {ciphertext, iv, burnSeconds}` | 201. burnSeconds in 15, 30, 60. Max 64 KB |
| Reveal | `POST /api/messages/:id/reveal` | Recipient only. Locked read-and-delete in one transaction. 404 if already burned |
| Live updates | `GET /api/events` | Server-sent events. Carry only `{"t":"change"}`, never content |

Limits: 10 sign-in/register attempts per 15 min per IP, 30 lookups per 5 min, 120 sends per 10 min. Unread messages burn after 7 days (sweeper).

## Differences from the first draft of this contract
Server-sent events instead of Socket.IO (no extra dependency, cookie-authenticated), opaque sessions instead of JWT (revocable), scrypt instead of argon2id (built into Node, no native build on Windows), plus account deletion for data-protection rights.

## Limits to state in the report
No forward secrecy (static device keys). A new device cannot read old chats. The server sees who talks to whom, when, and message sizes. Compare the safety number out of band.
