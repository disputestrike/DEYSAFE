const SHELL_CACHE = 'deysafe-shell-20260606-brand';
const SHELL_URLS = [
  '/', '/index.html', '/manifest.json', '/review.html',
  '/assets/brand/deysafe-icon-192.png',
  '/assets/brand/deysafe-icon-512.png',
  '/assets/brand/deysafe-apple-touch.png',
  '/assets/brand/deysafe-favicon.png'
];

self.addEventListener('install', function (event) {
  event.waitUntil(
    caches.open(SHELL_CACHE)
      .then(function (cache) { return cache.addAll(SHELL_URLS); })
      .catch(function () {})
      .then(function () { return self.skipWaiting(); })
  );
});

self.addEventListener('activate', function (event) {
  event.waitUntil(
    caches.keys()
      .then(function (keys) {
        return Promise.all(keys.map(function (key) {
          return key === SHELL_CACHE ? null : caches.delete(key);
        }));
      })
      .then(function () { return self.clients.claim(); })
  );
});

self.addEventListener('fetch', function (event) {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  if (url.origin === location.origin && url.pathname.startsWith('/api/')) {
    event.respondWith(fetch(req));
    return;
  }

  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req)
        .then(function (res) {
          const copy = res.clone();
          caches.open(SHELL_CACHE).then(function (cache) { cache.put('/index.html', copy); }).catch(function () {});
          return res;
        })
        .catch(function () {
          return caches.match('/index.html').then(function (res) {
            return res || new Response('DeySafe is offline and the app shell is not cached yet.', {
              status: 503,
              headers: { 'Content-Type': 'text/plain; charset=utf-8' }
            });
          });
        })
    );
    return;
  }

  event.respondWith(
    fetch(req)
      .then(function (res) {
        const cacheable = res && (res.ok || res.type === 'opaque');
        if (cacheable) {
          const copy = res.clone();
          caches.open(SHELL_CACHE).then(function (cache) { cache.put(req, copy); }).catch(function () {});
        }
        return res;
      })
      .catch(function () { return caches.match(req); })
  );
});
