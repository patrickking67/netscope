'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.join(__dirname, '..');
const source = fs.readFileSync(path.join(root, 'sw.js'), 'utf8');
const SCOPE = 'https://patrickking67.github.io/netscope/';

/** Load sw.js into a sandbox with a fake worker global and an in-memory cache. */
function loadWorker() {
  const listeners = {};
  const store = new Map();
  const cache = {
    addAll: async (urls) => urls.forEach((u) => store.set(new URL(u, SCOPE).href, 'shell')),
    put: async (request, response) => store.set(typeof request === 'string' ? request : request.url, response),
    match: async (request) => store.get(typeof request === 'string' ? new URL(request, SCOPE).href : request.url),
  };
  const context = {
    URL,
    console,
    Response: { error: () => ({ type: 'error' }) },
    caches: {
      open: async () => cache,
      keys: async () => [...store.keys()],
      match: (request) => cache.match(request),
      delete: async () => true,
    },
    fetch: async () => { throw new Error('fetch should not be called'); },
    self: {
      location: { href: SCOPE + 'sw.js', origin: 'https://patrickking67.github.io' },
      registration: { scope: SCOPE },
      addEventListener: (type, fn) => { listeners[type] = fn; },
      skipWaiting: () => {},
      clients: { claim: () => {} },
    },
  };
  vm.createContext(context);
  vm.runInContext(source, context);
  return { context, listeners, store };
}

function dispatchFetch(listeners, request) {
  let responded = null;
  const event = {
    request,
    respondWith: (promise) => { responded = promise; },
    waitUntil: () => {},
  };
  listeners.fetch(event);
  return responded;
}

test('isCacheableRequest only accepts GET requests inside the worker scope', () => {
  const { context } = loadWorker();
  const ok = (method, url) => context.isCacheableRequest(method, url, SCOPE);
  assert.equal(ok('GET', SCOPE + 'pages/app.html'), true);
  assert.equal(ok('GET', SCOPE + 'assets/js/core.js'), true);
  assert.equal(ok('POST', SCOPE + 'pages/app.html'), false);
  // Same origin but a different GitHub Pages project.
  assert.equal(ok('GET', 'https://patrickking67.github.io/other-project/index.html'), false);
  assert.equal(ok('GET', 'https://patrickking67.github.io/netscope-evil/index.html'), false);
  // Third-party APIs are never cached.
  assert.equal(ok('GET', 'https://api.pwnedpasswords.com/range/5BAA6'), false);
  assert.equal(ok('GET', 'https://dns.google/resolve?name=example.com&type=A'), false);
  assert.equal(ok('GET', 'not a url'), false);
});

test('isStorableResponse only stores successful same-origin responses', () => {
  const { context } = loadWorker();
  assert.equal(context.isStorableResponse({ ok: true, type: 'basic' }), true);
  assert.equal(context.isStorableResponse({ ok: false, status: 404, type: 'basic' }), false);
  assert.equal(context.isStorableResponse({ ok: false, status: 0, type: 'opaque' }), false);
  assert.equal(context.isStorableResponse(null), false);
});

test('fetch handler ignores third-party and out-of-scope requests', () => {
  const { listeners } = loadWorker();
  for (const url of ['https://api.xposedornot.com/v1/check-email/a%40b.com', 'https://patrickking67.github.io/other/']) {
    assert.equal(dispatchFetch(listeners, { method: 'GET', url, mode: 'cors' }), null, url);
  }
  assert.equal(dispatchFetch(listeners, { method: 'POST', url: SCOPE + 'x', mode: 'cors' }), null);
});

test('navigation does not cache error pages', async () => {
  const { context, listeners, store } = loadWorker();
  const url = SCOPE + 'pages/missing.html';
  context.fetch = async () => ({ ok: false, status: 404, type: 'basic', clone() { return this; } });
  const response = await dispatchFetch(listeners, { method: 'GET', url, mode: 'navigate' });
  assert.equal(response.status, 404);
  await new Promise((r) => setImmediate(r));
  assert.equal(store.has(url), false);
});

test('navigation falls back to the cached app shell when offline', async () => {
  const { context, listeners } = loadWorker();
  await listeners.install({ waitUntil: (p) => p });
  await new Promise((r) => setImmediate(r));
  context.fetch = async () => { throw new TypeError('offline'); };
  const response = await dispatchFetch(listeners, { method: 'GET', url: SCOPE + 'pages/never-cached.html', mode: 'navigate' });
  assert.equal(response, 'shell');
});

test('assets are served from cache and refreshed in the background', async () => {
  const { context, listeners, store } = loadWorker();
  const url = SCOPE + 'assets/js/app.js';
  store.set(url, 'old');
  let fetched = 0;
  const fresh = { ok: true, type: 'basic', clone() { return 'new'; } };
  context.fetch = async () => { fetched++; return fresh; };
  const response = await dispatchFetch(listeners, { method: 'GET', url, mode: 'no-cors' });
  assert.equal(response, 'old');
  await new Promise((r) => setImmediate(r));
  assert.equal(fetched, 1);
  assert.equal(store.get(url), 'new');
});

test('every file in the app shell exists in the repository', () => {
  const { context } = loadWorker();
  const shell = vm.runInContext('APP_SHELL', context);
  for (const entry of shell) {
    const file = entry === './' ? 'index.html' : entry.replace(/^\.\//, '');
    assert.ok(fs.existsSync(path.join(root, file)), `missing ${entry}`);
  }
});

test('every local script the pages load is in the app shell', () => {
  const { context } = loadWorker();
  const shell = new Set(vm.runInContext('APP_SHELL', context).map((e) => e.replace(/^\.\//, '')));
  const pages = ['index.html', 'pages/app.html', 'pages/about.html'];
  for (const page of pages) {
    const html = fs.readFileSync(path.join(root, page), 'utf8');
    for (const [, src] of html.matchAll(/<script[^>]+src="([^"]+)"/g)) {
      if (/^https?:/.test(src)) continue;
      const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(page), src));
      assert.ok(shell.has(resolved), `${page} loads ${resolved} but the service worker does not cache it`);
    }
  }
});
