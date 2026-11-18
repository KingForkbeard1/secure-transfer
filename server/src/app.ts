import express, { type Request, type Response, type NextFunction } from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { z } from 'zod';
import type { AccountStore } from './accounts.js';
import { chatRouter } from './chat-routes.js';
import { EventHub } from './events.js';
import type { SecretStore } from './store.js';

export const MAX_CIPHERTEXT_BYTES = 5 * 1024 * 1024 + 4096; // 5 MB payload + header + GCM tag
const ID_RE = /^[A-Za-z0-9_-]{22}$/;
const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const maxB64Len = Math.ceil((MAX_CIPHERTEXT_BYTES * 4) / 3) + 8;

export interface Limits { create: number; reveal: number; status: number; auth: number; lookup: number; send: number }
export interface AppOptions {
  secrets: SecretStore;
  accounts: AccountStore;
  hub?: EventHub;
  scryptN?: number;
  secureCookie?: boolean;
  now?: () => number;
  limits?: Partial<Limits>;
  clientDir?: string;
  trustProxy?: boolean;
}

const createBody = z.object({
  ciphertext: z.string().min(24).max(maxB64Len).regex(B64_RE),
  iv: z.string().length(16).regex(B64_RE), // 12 bytes
  kind: z.enum(['text', 'file']),
  ttl: z.union([z.literal(3600), z.literal(86400)]),
  salt: z.string().min(8).max(64).regex(B64_RE).optional(),
  verifier: z.string().min(16).max(128).regex(/^[A-Za-z0-9_-]+$/).optional(),
}).refine((b) => (b.salt === undefined) === (b.verifier === undefined), { message: 'salt and verifier go together' });

const revealBody = z.object({ verifier: z.string().min(16).max(128).regex(/^[A-Za-z0-9_-]+$/).optional() });

export function createApp(opts: AppOptions) {
  const { secrets: store, accounts } = opts;
  const hub = opts.hub ?? new EventHub();
  const now = opts.now ?? Date.now;
  const limits: Limits = { create: 20, reveal: 60, status: 1000, auth: 10, lookup: 30, send: 120, ...opts.limits };
  const app = express();
  app.disable('x-powered-by');
  if (opts.trustProxy) app.set('trust proxy', 1);

  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: false,
        directives: {
          'default-src': ["'self'"],
          'script-src': ["'self'"],
          'style-src': ["'self'"],
          'img-src': ["'self'", 'data:'],
          'connect-src': ["'self'"],
          'worker-src': ["'self'"],
          'manifest-src': ["'self'"],
          'object-src': ["'none'"],
          'base-uri': ["'none'"],
          'form-action': ["'self'"],
          'frame-ancestors': ["'none'"],
        },
      },
      referrerPolicy: { policy: 'no-referrer' },
      strictTransportSecurity: { maxAge: 15552000, includeSubDomains: true },
    }),
  );

  const mk = (max: number, windowMs: number) =>
    rateLimit({ windowMs, limit: max, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'rate-limited' } });
  const createLimiter = mk(limits.create, 3600_000);
  const revealLimiter = mk(limits.reveal, 3600_000);
  const statusLimiter = mk(limits.status, 900_000);

  const api = express.Router();
  api.use((_req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
  });
  api.use(express.json({ limit: '8mb' }));

  api.get('/health', (_req, res) => res.json({ ok: true }));

  api.post('/secrets', createLimiter, async (req, res) => {
    const parsed = createBody.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'invalid-request' });
    const b = parsed.data;
    const ciphertext = Buffer.from(b.ciphertext, 'base64');
    const iv = Buffer.from(b.iv, 'base64');
    if (iv.length !== 12 || ciphertext.length < 17 || ciphertext.length > MAX_CIPHERTEXT_BYTES) {
      return res.status(400).json({ error: 'invalid-request' });
    }
    const id = randomBytes(16).toString('base64url');
    const expiresAt = await store.create({
      id, ciphertext, iv, kind: b.kind, salt: b.salt ?? null, verifier: b.verifier ?? null,
      now: now(), ttlSeconds: b.ttl,
    });
    res.status(201).json({ id, expiresAt });
  });

  const withId = (req: Request, res: Response, next: NextFunction) => {
    if (!ID_RE.test(String(req.params.id))) return res.status(404).json({ error: 'gone' });
    next();
  };

  // Read-only: shows the landing page info. Never destroys data.
  api.get('/secrets/:id', statusLimiter, withId, async (req, res) => {
    const m = await store.meta(String(req.params.id), now());
    if (!m) return res.status(404).json({ error: 'gone' });
    res.json(m);
  });

  api.post('/secrets/:id/reveal', revealLimiter, withId, async (req, res) => {
    const parsed = revealBody.safeParse(req.body ?? {});
    if (!parsed.success) return res.status(400).json({ error: 'invalid-request' });
    const r = await store.reveal(String(req.params.id), parsed.data.verifier ?? null, now());
    if (r.ok) {
      return res.json({ ciphertext: r.ciphertext.toString('base64'), iv: r.iv.toString('base64'), kind: r.kind });
    }
    if (r.reason === 'bad-verifier') return res.status(401).json({ error: 'bad-passphrase', attemptsLeft: r.attemptsLeft });
    res.status(404).json({ error: 'gone' });
  });

  api.get('/secrets/:id/status', statusLimiter, withId, async (req, res) => {
    const s = await store.status(String(req.params.id), now());
    if (!s) return res.status(404).json({ status: 'unknown' });
    res.json({ status: s });
  });

  api.use(chatRouter({ accounts, hub, now, scryptN: opts.scryptN, secureCookie: opts.secureCookie ?? false, limits: { auth: limits.auth, lookup: limits.lookup, send: limits.send } }));

  api.use((_req, res) => res.status(404).json({ error: 'not-found' }));
  api.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    const e = err as { status?: number; type?: string };
    if (e?.type === 'entity.too.large') return res.status(413).json({ error: 'too-large' });
    if (e?.status && e.status < 500) return res.status(e.status).json({ error: 'invalid-request' });
    res.status(500).json({ error: 'server-error' }); // never echo internals
  });
  app.use('/api', api);

  if (opts.clientDir && existsSync(opts.clientDir)) {
    app.use(express.static(opts.clientDir, { index: false, maxAge: '1h' }));
    app.get(/^(?!\/api\/).*/, (_req, res) => {
      res.setHeader('Cache-Control', 'no-cache');
      res.sendFile(path.join(opts.clientDir!, 'index.html'));
    });
  }
  return app;
}
