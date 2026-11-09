'use strict';

// Static checks on the HTML so security headers and privacy rules do not regress.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const pages = ['index.html', 'pages/app.html', 'pages/about.html'];
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

function csp(html) {
  const match = html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)">/);
  if (!match) return null;
  const directives = {};
  for (const part of match[1].split(';')) {
    const [name, ...values] = part.trim().split(/\s+/);
    if (name) directives[name] = values;
  }
  return directives;
}

for (const page of pages) {
  test(`${page} declares a restrictive Content-Security-Policy`, () => {
    const policy = csp(read(page));
    assert.ok(policy, 'CSP meta tag missing');
    assert.deepEqual(policy['object-src'], ["'none'"]);
    assert.deepEqual(policy['base-uri'], ["'self'"]);
    assert.ok(policy['script-src'], 'script-src missing');
    assert.ok(!policy['script-src'].includes("'unsafe-inline'"), 'inline scripts must not be allowed');
    assert.ok(!policy['script-src'].includes("'unsafe-eval'"), 'eval must not be allowed');
    assert.ok(!policy['script-src'].includes('*'), 'wildcard script hosts are not allowed');
  });

  test(`${page} has no inline scripts or inline event handlers`, () => {
    const html = read(page);
    for (const [tag] of html.matchAll(/<script\b[^>]*>/g)) {
      assert.match(tag, /\ssrc="/, `inline script found: ${tag}`);
    }
    assert.ok(!/\son[a-z]+\s*=\s*["']/i.test(html), 'inline event handler found');
    assert.ok(!/href\s*=\s*["']javascript:/i.test(html), 'javascript: URL found');
  });

  test(`${page} has a skip link to its main landmark and a theme color`, () => {
    const html = read(page);
    assert.match(html, /<a class="skip-link" href="#main">/);
    assert.equal([...html.matchAll(/<main\b[^>]*\bid="main"/g)].length, 1, 'exactly one <main id="main">');
    assert.match(html, /<meta name="theme-color" content="#[0-9a-f]{6}">/);
  });

  test(`${page} links that open new tabs use rel=noopener`, () => {
    const html = read(page);
    for (const [tag] of html.matchAll(/<a\b[^>]*target="_blank"[^>]*>/g)) {
      assert.match(tag, /rel="[^"]*noopener/, tag);
    }
  });
}

test('third-party scripts that publish integrity hashes are pinned with SRI', () => {
  const html = read('pages/app.html');
  for (const [tag] of html.matchAll(/<script[^>]+src="https:\/\/(?:unpkg\.com|cdnjs\.cloudflare\.com)[^"]+"[^>]*>/g)) {
    assert.match(tag, /integrity="sha(256|384|512)-/, tag);
    assert.match(tag, /crossorigin=/, tag);
  }
});

test('app CSP allows every API host the code calls', () => {
  const policy = csp(read('pages/app.html'));
  const connect = policy['connect-src'];
  const sources = ['assets/js/app.js', 'assets/js/core.js'].map(read).join('\n');
  // Every https:// origin that starts a string or template literal in the scripts.
  const hosts = new Set([...sources.matchAll(/['"`](https:\/\/[a-z0-9.-]+)/gi)].map((m) => m[1].toLowerCase()));
  assert.ok(hosts.size >= 10, `expected to discover the API hosts, found ${[...hosts].join(', ')}`);
  // Link-only destinations are not fetched by the page.
  const ignored = new Set(['https://haveibeenpwned.com']);
  for (const host of hosts) {
    if (ignored.has(host)) continue;
    const allowed = connect.includes(host) || connect.some((c) => c.startsWith('https://*.') && host.endsWith(c.slice('https://*'.length)));
    assert.ok(allowed, `connect-src does not allow ${host}`);
  }
});

test('app.html loads core.js before the scripts that depend on it', () => {
  const html = read('pages/app.html');
  const order = [...html.matchAll(/<script[^>]+src="([^"]+)"/g)].map((m) => m[1]);
  const core = order.indexOf('../assets/js/core.js');
  assert.ok(core !== -1, 'core.js is not loaded');
  assert.ok(core < order.indexOf('../assets/js/auth.js'));
  assert.ok(core < order.indexOf('../assets/js/app.js'));
});

test('password input is never stored, exported or sent anywhere but the k-anonymity check', () => {
  const app = read('assets/js/app.js');
  const usages = [...app.matchAll(/password-input/g)].length;
  // Bound in initPasswordToggle, initEventListeners and read once in checkPasswordBreach.
  assert.equal(usages, 3);
  assert.ok(!/localStorage\.setItem\([^)]*password/i.test(app));
  assert.match(app, /state\.breach\.password = \{ count \}/);
});

test('app tool tabs follow the ARIA tabs pattern', () => {
  const html = read('pages/app.html');
  const tabs = [...html.matchAll(/<button[^>]+class="tab-bar-item[^"]*"[^>]*>/g)].map((m) => m[0]);
  assert.equal(tabs.length, 5);
  for (const tab of tabs) {
    const id = tab.match(/data-tab="([a-z-]+)"/)[1];
    assert.match(tab, /role="tab"/);
    assert.match(tab, new RegExp(`aria-controls="panel-${id}"`));
    assert.match(html, new RegExp(`id="panel-${id}"[^>]*role="tabpanel"[^>]*aria-labelledby="tab-${id}"`));
  }
  assert.equal(tabs.filter((t) => /aria-selected="true"/.test(t)).length, 1);
});

test('app result regions announce updates and icon-only controls have names', () => {
  const html = read('pages/app.html');
  for (const id of ['email-result', 'password-result', 'scan-results', 'toast']) {
    assert.match(html, new RegExp(`id="${id}"[^>]*aria-live="polite"`), id);
  }
  for (const id of ['toggle-password', 'pwgen-copy', 'export-trigger', 'btn-full-scan']) {
    assert.match(html, new RegExp(`id="${id}"[^>]*aria-label="[^"]+"`), id);
  }
  for (const id of ['email-input', 'password-input', 'scan-input']) {
    assert.match(html, new RegExp(`id="${id}"[^>]*aria-label="[^"]+"`), id);
  }
});

test('every third-party call in app.js goes through the timeout helper', () => {
  const app = read('assets/js/app.js');
  // Speed test requests use plain fetch, but each one must carry a deadline signal from the speed test.
  for (const [line] of app.matchAll(/^.*\bfetch\(.*$/gm)) {
    assert.match(line, /speed\.cloudflare\.com|generate_204|fetch\(url, /, `untimed fetch: ${line.trim()}`);
    assert.match(line, /signal: (deadline\.signal|pingSignal|transferSignal)/, `speed test fetch without a deadline: ${line.trim()}`);
  }
  assert.match(app, /Core\.checkEmailExposure\(email, \{ fetchImpl: timedFetch \}\)/);
  assert.match(app, /Core\.checkPwnedPassword\(password, \{ fetchImpl: timedFetch \}\)/);
});
