self.addEventListener('install', event => {
    event.waitUntil(
      caches.open('scam-detector-cache').then(cache => {
        return cache.addAll([
          '/',
          '/index.html',
          '/popup.html',
          '/assets/icons/icon-72x72.png',
          '/assets/icons/icon-96x96.png',
          '/assets/icons/icon-128x128.png',
          '/assets/icons/icon-144x144.png',
          '/assets/icons/icon-152x152.png',
          '/assets/icons/icon-192x192.png',
          '/assets/icons/icon-384x384.png',
          '/assets/icons/icon-512x512.png',
          '/assets/screenshots/screenshot-mob.png',
          '/assets/screenshots/screenshot-web.png',
          '/src/js/detector.js',
          '/src/js/popup.js', // and other necessary files
        ]);
      })
    );
  });
  
  self.addEventListener('fetch', event => {
    event.respondWith(
      caches.match(event.request).then(response => {
        return response || fetch(event.request);
      })
    );
  });
  