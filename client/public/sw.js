// App-shell cache only. API responses (which can carry ciphertext) are never cached.
const CACHE = 'st-shell-v1';
self.addEventListener('install', (e) => {
  self.skipWaiting();
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(['/', '/manifest.webmanifest', '/icon-192.png'])));
});
self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim()),
  );
});
self.addEventListener('fetch', (e) => {
  const u = new URL(e.request.url);
  if (e.request.method !== 'GET' || u.origin !== self.location.origin || u.pathname.startsWith('/api/')) return;
  const nav = e.request.mode === 'navigate';
  e.respondWith(
    fetch(e.request)
      .then((r) => {
        if (r.ok && (nav || u.pathname.startsWith('/assets/'))) {
          const copy = r.clone();
          caches.open(CACHE).then((c) => c.put(nav ? '/' : e.request, copy));
        }
        return r;
      })
      .catch(() => caches.match(nav ? '/' : e.request)),
  );
});
