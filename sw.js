const V = "ps5poc-diagnostics-v14";

const SHELL = [
  "./",
  "./index.html",
  "./exploit.html",
  "./modules/offsets.mjs",
  "./modules/native_provider.js?v=14",
  "./modules/krw_provider.js?v=14",
  "./modules/kernel_bagagwa.js?v=14",
  "./modules/exploit.js?v=14",
];

self.addEventListener("install", e => {
  e.waitUntil(
    caches.open(V)
      .then(c => c.addAll(SHELL))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", e => {
  e.waitUntil(
    caches.keys()
      .then(keys =>
        Promise.all(
          keys
            .filter(key => key !== V)
            .map(key => caches.delete(key))
        )
      )
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", e => {
  if (e.request.method !== "GET") return;

  e.respondWith(
    caches.match(e.request).then(cached => {
      const network = fetch(e.request)
        .then(response => {
          if (response.ok) {
            const copy = response.clone();

            caches.open(V).then(cache => {
              cache.put(e.request, copy);
            });
          }

          return response;
        })
        .catch(() => null);

      return cached || network;
    })
  );
});
