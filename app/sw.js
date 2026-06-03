// KILL-SWITCH service worker.
// Any browser still holding an old cached app will fetch this on its next visit,
// which unregisters the stale worker and clears all caches so the fresh app loads.
// (A versioned offline SW can be re-added for production later.)
self.addEventListener('install', function () { self.skipWaiting(); });
self.addEventListener('activate', function (e) {
  e.waitUntil((async function () {
    try { const ks = await caches.keys(); await Promise.all(ks.map(function (k) { return caches.delete(k); })); } catch (_) {}
    try { await self.registration.unregister(); } catch (_) {}
    try { const cs = await self.clients.matchAll(); cs.forEach(function (c) { c.navigate(c.url); }); } catch (_) {}
  })());
});
// No fetch interception — always go to the network.
self.addEventListener('fetch', function () {});
