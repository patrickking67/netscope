// Bump the version whenever APP_SHELL or caching behavior changes.
const CACHE_NAME = "netscope-shell-v4";
const APP_SHELL = [
  "./",
  "./index.html",
  "./pages/app.html",
  "./pages/about.html",
  "./manifest.webmanifest",
  "./assets/css/style.css",
  "./assets/js/core.js",
  "./assets/js/app.js",
  "./assets/js/auth.js",
  "./assets/js/firestore.js",
  "./assets/js/firebase-config.js",
  "./assets/js/pwa.js",
  "./assets/js/theme-init.js",
  "./assets/js/site.js",
  "./assets/images/favicon.svg",
  "./assets/images/logo-dark.svg",
  "./assets/images/logo-light.svg",
  "./assets/images/logo-icon.svg"
];

/**
 * Only same-origin GET requests inside this worker's scope are cached.
 * GitHub Pages serves every project site for an account from one origin, so
 * the scope check keeps this worker from caching other projects' files.
 * Third-party API calls (IP, breach, DNS, speed test) are never intercepted,
 * so their results are never written to the cache.
 */
function isCacheableRequest(method, url, scope) {
  if (method !== "GET") return false;
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return false;
  return parsed.href.startsWith(scope);
}

/** Only store complete, same-origin, successful responses. */
function isStorableResponse(response) {
  return Boolean(response) && response.ok && response.type === "basic";
}

function workerScope() {
  return (self.registration && self.registration.scope) || new URL("./", self.location.href).href;
}

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(APP_SHELL)));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((key) => key.startsWith("netscope-") && key !== CACHE_NAME).map((key) => caches.delete(key)))
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (!isCacheableRequest(request.method, request.url, workerScope())) return;

  if (request.mode === "navigate") {
    // Network first so a fresh deploy is picked up on the next visit.
    event.respondWith(
      fetch(request)
        .then((response) => {
          if (isStorableResponse(response)) {
            const copy = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
          }
          return response;
        })
        .catch(() => caches.match(request).then((cached) => cached || caches.match("./pages/app.html")))
    );
    return;
  }

  // Stale while revalidate: answer from cache, refresh the cache in the background.
  event.respondWith(
    caches.open(CACHE_NAME).then((cache) =>
      cache.match(request).then((cached) => {
        const network = fetch(request)
          .then((response) => {
            if (isStorableResponse(response)) cache.put(request, response.clone());
            return response;
          })
          .catch(() => cached || Response.error());
        if (cached) {
          event.waitUntil(network);
          return cached;
        }
        return network;
      })
    )
  );
});
