// Offline cache for My Cashbook. Raise the number in CACHE_NAME every time you upload new files.
const CACHE_NAME = 'my-cashbook-shell-v19';

// The app cannot work offline without these. If one cannot be downloaded, the update is not installed.
const CORE_FILES = ['./', './index.html', './styles.css', './app.js', './manifest.webmanifest', './icon.svg'];

// Nice to have. A missing file here never breaks offline mode.
const OPTIONAL_FILES = [
  './privacy.html',
  './fonts/dm-sans-400.woff2',
  './fonts/dm-sans-500.woff2',
  './fonts/dm-sans-600.woff2',
  './fonts/dm-sans-700.woff2',
  './fonts/manrope-400.woff2',
  './fonts/manrope-500.woff2',
  './fonts/manrope-600.woff2',
  './fonts/manrope-700.woff2',
  './fonts/manrope-800.woff2',
];

// Some hosts (for example Cloudflare) redirect /privacy.html to /privacy. Browsers refuse to show a redirected
// response from a service worker, so store and serve a clean copy instead.
async function cleanCopy(response) {
  if (!response || !response.redirected) return response;
  const body = await response.blob();
  return new Response(body, { status: response.status, statusText: response.statusText, headers: response.headers });
}

async function cacheFile(cache, url) {
  const response = await fetch(url, { cache: 'reload' });
  if (!response.ok) throw new Error(url + ' returned ' + response.status);
  await cache.put(url, await cleanCopy(response));
}

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_NAME);
    await Promise.all(CORE_FILES.map((url) => cacheFile(cache, url)));
    await Promise.allSettled(OPTIONAL_FILES.map((url) => cacheFile(cache, url)));
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  const requestUrl = new URL(event.request.url);
  if (requestUrl.origin !== self.location.origin) return;
  event.respondWith((async () => {
    // ignoreSearch: opening the app as "/?source=pwa" or from a link with extra text still finds the saved page.
    const cached = await caches.match(event.request, { ignoreSearch: true });
    if (cached) return cleanCopy(cached);
    try {
      const response = await fetch(event.request);
      if (response.ok && !response.redirected) {
        const copy = response.clone();
        void caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
      }
      return response;
    } catch {
      if (event.request.mode === 'navigate') {
        const home = (await caches.match('./')) || (await caches.match('./index.html'));
        if (home) return cleanCopy(home);
      }
      return Response.error();
    }
  })());
});
