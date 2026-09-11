/**
 * Service Worker for offline capability
 */

const CACHE_NAME = 'research-framework-v1';
const urlsToCache = [
    '/',
    '/exploit.html',
    '/modules/framework.js',
    '/modules/exploit.js',
    '/modules/kernel_bagagwa.js'
];

self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => cache.addAll(urlsToCache))
    );
});

self.addEventListener('fetch', (event) => {
    event.respondWith(
        caches.match(event.request)
            .then(response => response || fetch(event.request))
    );
});