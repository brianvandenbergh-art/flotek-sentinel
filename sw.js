self.addEventListener('install', (event) => {
    self.skipWaiting();
});

self.addEventListener('activate', (event) => {
    event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', (event) => {
    // Network-first fetch for live fleet operations
    event.respondWith(fetch(event.request).catch(() => caches.match(event.request)));
});
