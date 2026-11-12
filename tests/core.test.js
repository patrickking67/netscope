'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const Core = require('../assets/js/core.js');

// ------------------------------------------------------------
// Helpers
// ------------------------------------------------------------
function fakeResponse({ status = 200, body = '', json } = {}) {
  return {
    status,
    ok: status >= 200 && status < 300,
    text: async () => body,
    json: async () => (json !== undefined ? json : JSON.parse(body)),
  };
}

function recordingFetch(handler) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    return handler(url, init);
  };
  return { calls, fetchImpl };
}

// Deterministic getRandomValues that replays a list of 32-bit values.
function scriptedRandom(values) {
  let i = 0;
  return (array) => {
    for (let j = 0; j < array.length; j++) array[j] = values[i++ % values.length];
    return array;
  };
}

// ------------------------------------------------------------
// HTML escaping
// ------------------------------------------------------------
test('escapeHtml escapes markup and both quote styles', () => {
  assert.equal(Core.escapeHtml('<img src=x onerror="alert(1)">'), '&lt;img src=x onerror=&quot;alert(1)&quot;&gt;');
  assert.equal(Core.escapeHtml("it's & <b>"), 'it&#39;s &amp; &lt;b&gt;');
  assert.equal(Core.escapeHtml(null), '');
  assert.equal(Core.escapeHtml(undefined), '');
  assert.equal(Core.escapeHtml(42), '42');
});

test('escapeHtml output cannot break out of a quoted attribute', () => {
  const hostile = '" onmouseover="alert(1)';
  const html = `<button data-id="${Core.escapeHtml(hostile)}">`;
  assert.ok(!html.includes('" onmouseover="'));
});

// ------------------------------------------------------------
// Pwned Passwords k-anonymity
// ------------------------------------------------------------
test('sha1Hex matches Node crypto and is uppercase', async () => {
  const expected = crypto.createHash('sha1').update('correct horse battery staple', 'utf8').digest('hex').toUpperCase();
  assert.equal(await Core.sha1Hex('correct horse battery staple'), expected);
  // Well-known vector: SHA-1("password")
  assert.equal(await Core.sha1Hex('password'), '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');
});

test('sha1Hex hashes non-ASCII input as UTF-8', async () => {
  const expected = crypto.createHash('sha1').update('pässwörd-密码', 'utf8').digest('hex').toUpperCase();
  assert.equal(await Core.sha1Hex('pässwörd-密码'), expected);
});

test('splitPwnedHash returns a 5 character prefix and 35 character suffix', () => {
  const { prefix, suffix } = Core.splitPwnedHash('5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8');
  assert.equal(prefix, '5BAA6');
  assert.equal(suffix, '1E4C9B93F3F0682250B6CF8331B7EE68FD8');
  assert.equal(prefix.length + suffix.length, 40);
  assert.throws(() => Core.splitPwnedHash('not-a-hash'));
});

test('buildPwnedRangeUrl refuses anything longer or shorter than a 5 character prefix', () => {
  assert.equal(Core.buildPwnedRangeUrl('5BAA6'), 'https://api.pwnedpasswords.com/range/5BAA6');
  assert.throws(() => Core.buildPwnedRangeUrl('5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8'));
  assert.throws(() => Core.buildPwnedRangeUrl('5BAA'));
  assert.throws(() => Core.buildPwnedRangeUrl('password'));
  assert.throws(() => Core.buildPwnedRangeUrl('5baa6'));
});

test('parsePwnedRange finds the count, tolerates CRLF and ignores padding rows', () => {
  const body = [
    '003D68EB55068C33ACE09247EE4C639306B:3',
    '1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365',
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0',
    '',
  ].join('\r\n');
  assert.equal(Core.parsePwnedRange(body, '1E4C9B93F3F0682250B6CF8331B7EE68FD8'), 9659365);
  assert.equal(Core.parsePwnedRange(body, '1e4c9b93f3f0682250b6cf8331b7ee68fd8'), 9659365);
  assert.equal(Core.parsePwnedRange(body, 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'), 0);
  assert.equal(Core.parsePwnedRange(body, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'), 0);
  assert.equal(Core.parsePwnedRange('', 'AAAA'), 0);
});

test('checkPwnedPassword sends only the hash prefix, never the password or full hash', async () => {
  const password = 'hunter2-Example!';
  const fullHash = crypto.createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase();
  const suffix = fullHash.slice(5);
  const { calls, fetchImpl } = recordingFetch(() => fakeResponse({ body: `${suffix}:42\nABC:1` }));

  const result = await Core.checkPwnedPassword(password, { fetchImpl });

  assert.equal(result.count, 42);
  assert.equal(calls.length, 1);
  const { url, init } = calls[0];
  assert.equal(url, `https://api.pwnedpasswords.com/range/${fullHash.slice(0, 5)}`);
  const sent = url + JSON.stringify(init);
  assert.ok(!sent.includes(password), 'password must not be sent');
  assert.ok(!sent.toUpperCase().includes(fullHash), 'full hash must not be sent');
  assert.ok(!sent.toUpperCase().includes(suffix), 'hash suffix must not be sent');
  assert.equal(init.headers['Add-Padding'], 'true');
  assert.equal(init.referrerPolicy, 'no-referrer');
  assert.equal(init.method, undefined, 'range lookup is a GET with no body');
  assert.equal(init.body, undefined);
});

test('checkPwnedPassword throws on HTTP errors instead of reporting the password as safe', async () => {
  for (const status of [429, 500, 503]) {
    const { fetchImpl } = recordingFetch(() => fakeResponse({ status, body: 'Too many requests' }));
    await assert.rejects(Core.checkPwnedPassword('anything', { fetchImpl }), /HTTP/);
  }
});

test('checkPwnedPassword rejects empty input without any network call', async () => {
  const { calls, fetchImpl } = recordingFetch(() => fakeResponse());
  await assert.rejects(Core.checkPwnedPassword('', { fetchImpl }));
  assert.equal(calls.length, 0);
});

// ------------------------------------------------------------
// Email breach check
// ------------------------------------------------------------
test('isPlausibleEmail accepts normal addresses and rejects junk', () => {
  assert.ok(Core.isPlausibleEmail('person@example.com'));
  assert.ok(Core.isPlausibleEmail('  first.last+tag@sub.example.co.uk '));
  for (const bad of ['', 'no-at-sign', 'a@b', '@example.com', 'a b@example.com', `${'a'.repeat(250)}@x.io`]) {
    assert.ok(!Core.isPlausibleEmail(bad), bad);
  }
});

test('normalizeXposedBreaches flattens the check-email array of arrays', () => {
  const data = { breaches: [['Adobe', 'LinkedIn', 'Adobe']], email: 'person@example.com', status: 'success' };
  assert.deepEqual(Core.normalizeXposedBreaches(data), [{ name: 'Adobe' }, { name: 'LinkedIn' }]);
});

test('normalizeXposedBreaches reads the breach-analytics shape', () => {
  const data = { ExposedBreaches: { breaches_details: [{ breach: 'Canva', domain: 'canva.com' }, { breach: '' }] } };
  assert.deepEqual(Core.normalizeXposedBreaches(data), [{ name: 'Canva', domain: 'canva.com' }]);
});

test('normalizeXposedBreaches handles empty and unexpected input', () => {
  assert.deepEqual(Core.normalizeXposedBreaches(null), []);
  assert.deepEqual(Core.normalizeXposedBreaches({ Error: 'Not found', email: null }), []);
  assert.deepEqual(Core.normalizeXposedBreaches({ breaches: 'Adobe' }), []);
});

test('checkEmailExposure reports found breaches', async () => {
  const { calls, fetchImpl } = recordingFetch(() => fakeResponse({ json: { breaches: [['Adobe', 'Dropbox']] } }));
  const result = await Core.checkEmailExposure('person@example.com', { fetchImpl });
  assert.equal(result.status, 'found');
  assert.equal(result.breaches.length, 2);
  assert.equal(calls[0].url, 'https://api.xposedornot.com/v1/check-email/person%40example.com');
});

test('checkEmailExposure treats 404 as clean', async () => {
  const { fetchImpl } = recordingFetch(() => fakeResponse({ status: 404, json: { Error: 'Not found', email: null } }));
  const result = await Core.checkEmailExposure('person@example.com', { fetchImpl });
  assert.equal(result.status, 'clean');
});

test('checkEmailExposure reports rate limits and server errors as errors, not clean', async () => {
  for (const status of [429, 500, 502]) {
    const { fetchImpl } = recordingFetch(() => fakeResponse({ status, body: 'error' }));
    const result = await Core.checkEmailExposure('person@example.com', { fetchImpl });
    assert.equal(result.status, 'error', `HTTP ${status}`);
    assert.equal(result.httpStatus, status);
  }
});

test('checkEmailExposure falls back to breach-analytics only on network failure', async () => {
  const { calls, fetchImpl } = recordingFetch((url) => {
    if (url.includes('check-email')) throw new TypeError('Failed to fetch');
    return fakeResponse({ json: { ExposedBreaches: { breaches_details: [{ breach: 'Canva', domain: 'canva.com' }] } } });
  });
  const result = await Core.checkEmailExposure('person@example.com', { fetchImpl });
  assert.equal(calls.length, 2);
  assert.ok(calls[1].url.startsWith('https://api.xposedornot.com/v1/breach-analytics?email='));
  assert.equal(result.status, 'found');
});

test('checkEmailExposure returns error when both endpoints fail', async () => {
  const fetchImpl = async () => { throw new TypeError('offline'); };
  const result = await Core.checkEmailExposure('person@example.com', { fetchImpl });
  assert.equal(result.status, 'error');
});

test('checkEmailExposure rejects invalid input without a network call', async () => {
  const { calls, fetchImpl } = recordingFetch(() => fakeResponse());
  await assert.rejects(Core.checkEmailExposure('not-an-email', { fetchImpl }));
  assert.equal(calls.length, 0);
});

// ------------------------------------------------------------
// DNS input and record analysis
// ------------------------------------------------------------
test('normalizeDomainInput extracts the domain from URLs and email addresses', () => {
  assert.equal(Core.normalizeDomainInput('Example.COM'), 'example.com');
  assert.equal(Core.normalizeDomainInput('https://www.example.com/path?q=1#x'), 'www.example.com');
  assert.equal(Core.normalizeDomainInput('http://example.com:8080'), 'example.com');
  assert.equal(Core.normalizeDomainInput('person@mail.example.org'), 'mail.example.org');
  assert.equal(Core.normalizeDomainInput('https://user@example.net/'), 'example.net');
  assert.equal(Core.normalizeDomainInput('example.com.'), 'example.com');
  assert.equal(Core.normalizeDomainInput('xn--bcher-kva.example'), 'xn--bcher-kva.example');
});

test('normalizeDomainInput rejects values that are not domains', () => {
  for (const bad of ['', 'localhost', '-bad.com', 'bad-.com', 'exa mple.com', 'example..com', '192.168.1.1', 'a.' + 'b'.repeat(64) + '.com', '<script>.com']) {
    assert.equal(Core.normalizeDomainInput(bad), null, bad);
  }
});

test('joinTxtData joins quoted DoH TXT segments and unescapes quotes', () => {
  assert.equal(Core.joinTxtData('"v=spf1 include:_spf.example.com" " -all"'), 'v=spf1 include:_spf.example.com -all');
  assert.equal(Core.joinTxtData('v=spf1 -all'), 'v=spf1 -all');
  assert.equal(Core.joinTxtData('"say \\"hi\\""'), 'say "hi"');
});

test('txtValues keeps only TXT answers', () => {
  const response = { Answer: [{ type: 5, data: 'alias.example.com.' }, { type: 16, data: '"v=spf1 -all"' }] };
  assert.deepEqual(Core.txtValues(response), ['v=spf1 -all']);
  assert.deepEqual(Core.txtValues({}), []);
});

test('evaluateSpf grades SPF records', () => {
  assert.equal(Core.evaluateSpf([]).icon, 'fail');
  assert.equal(Core.evaluateSpf(['google-site-verification=abc']).icon, 'fail');
  assert.equal(Core.evaluateSpf(['v=spf1 include:_spf.google.com ~all']).icon, 'pass');
  assert.equal(Core.evaluateSpf(['v=spf1 mx -all']).icon, 'pass');
  assert.equal(Core.evaluateSpf(['v=spf1 +all']).icon, 'fail');
  assert.equal(Core.evaluateSpf(['v=spf1 a all']).icon, 'fail');
  assert.equal(Core.evaluateSpf(['v=spf1 a ?all']).icon, 'warn');
  const duplicate = Core.evaluateSpf(['v=spf1 -all', 'v=spf1 mx -all']);
  assert.equal(duplicate.icon, 'fail');
  assert.match(duplicate.detail, /Multiple/);
});

test('parseDmarcTags reads tags and keeps the first occurrence', () => {
  assert.deepEqual(Core.parseDmarcTags('v=DMARC1; p=reject; rua=mailto:d@example.com'), {
    v: 'DMARC1', p: 'reject', rua: 'mailto:d@example.com',
  });
});

test('evaluateDmarc reads p= and is not fooled by sp=', () => {
  // Regression: the old regex /p=(\w+)/ matched the "p=" inside "sp=none".
  const result = Core.evaluateDmarc(['v=DMARC1; sp=none; p=reject']);
  assert.equal(result.icon, 'pass');
  assert.equal(result.detail, 'Policy: reject');
  assert.equal(Core.evaluateDmarc(['v=DMARC1; p=quarantine; pct=100']).icon, 'pass');
  assert.equal(Core.evaluateDmarc(['v=DMARC1; p=none']).icon, 'warn');
  assert.equal(Core.evaluateDmarc(['v=DMARC1; rua=mailto:x@example.com']).icon, 'warn');
  assert.equal(Core.evaluateDmarc([]).icon, 'fail');
  assert.equal(Core.evaluateDmarc(['v=DMARC1; p=reject', 'v=DMARC1; p=none']).icon, 'fail');
});

test('hasDkimKey requires a non-empty public key', () => {
  assert.ok(Core.hasDkimKey(['v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA']));
  assert.ok(!Core.hasDkimKey(['v=DKIM1; p=']), 'empty p= means the key was revoked');
  assert.ok(!Core.hasDkimKey(['v=spf1 -all']));
  assert.ok(!Core.hasDkimKey([]));
});

test('evaluateDnssec uses the AD flag', () => {
  assert.equal(Core.evaluateDnssec({ AD: true }).icon, 'pass');
  assert.equal(Core.evaluateDnssec({ AD: false }).icon, 'warn');
  assert.equal(Core.evaluateDnssec(null).icon, 'warn');
});

test('dnsTypeName maps known codes and labels unknown ones', () => {
  assert.equal(Core.dnsTypeName(1), 'A');
  assert.equal(Core.dnsTypeName(28), 'AAAA');
  assert.equal(Core.dnsTypeName(15), 'MX');
  assert.equal(Core.dnsTypeName(99), 'TYPE99');
  assert.equal(Core.dnsTypeName('<b>'), 'TYPE?');
});

// ------------------------------------------------------------
// WebRTC leak detection
// ------------------------------------------------------------
test('isPrivateIPv4 covers RFC 1918, loopback, link-local and CGNAT', () => {
  for (const ip of ['10.0.0.1', '172.16.0.1', '172.31.255.255', '192.168.1.20', '127.0.0.1', '169.254.1.1', '100.64.0.1']) {
    assert.ok(Core.isPrivateIPv4(ip), ip);
  }
  for (const ip of ['8.8.8.8', '172.32.0.1', '192.169.0.1', '100.128.0.1', '256.1.1.1', 'not-an-ip']) {
    assert.ok(!Core.isPrivateIPv4(ip), ip);
  }
});

test('parseIceCandidate reads address and type', () => {
  const parsed = Core.parseIceCandidate('candidate:842163049 1 udp 1677729535 203.0.113.7 56143 typ srflx raddr 0.0.0.0 rport 0 generation 0');
  assert.deepEqual(parsed, { protocol: 'udp', address: '203.0.113.7', type: 'srflx' });
  assert.equal(Core.parseIceCandidate('garbage'), null);
});

test('classifyIceCandidates separates local leaks from the STUN public address', () => {
  const result = Core.classifyIceCandidates([
    'candidate:1 1 udp 2122260223 3f1b2c4d-1111-2222-3333-444455556666.local 54321 typ host generation 0',
    'candidate:2 1 udp 2122260223 192.168.1.20 54322 typ host generation 0',
    'candidate:3 1 udp 2122260223 2001:db8::1 54323 typ host generation 0',
    'candidate:4 1 udp 1677729535 203.0.113.7 56143 typ srflx raddr 0.0.0.0 rport 0',
  ]);
  assert.deepEqual(result.localAddresses, ['192.168.1.20', '2001:db8::1']);
  assert.deepEqual(result.publicAddresses, ['203.0.113.7']);
});

test('evaluateWebRtc does not flag the normal STUN public address as a local leak', () => {
  // Regression: the old check reported the srflx public address as "Local IPs detected".
  const classified = { localAddresses: [], publicAddresses: ['203.0.113.7'] };
  assert.equal(Core.evaluateWebRtc(classified, '203.0.113.7').icon, 'pass');
  assert.equal(Core.evaluateWebRtc(classified, null).icon, 'pass');
});

test('evaluateWebRtc flags local addresses and VPN mismatches', () => {
  assert.equal(Core.evaluateWebRtc({ localAddresses: ['192.168.1.20'], publicAddresses: [] }, null).icon, 'warn');
  const mismatch = Core.evaluateWebRtc({ localAddresses: [], publicAddresses: ['198.51.100.9'] }, '203.0.113.7');
  assert.equal(mismatch.icon, 'warn');
  assert.match(mismatch.detail, /VPN/);
  // Different address families are not compared.
  assert.equal(Core.evaluateWebRtc({ localAddresses: [], publicAddresses: ['2001:db8::5'] }, '203.0.113.7').icon, 'pass');
});

// ------------------------------------------------------------
// Password generator
// ------------------------------------------------------------
test('secureRandomInt rejects values that would cause modulo bias', () => {
  // For max = 10, values >= 4294967290 must be rejected and redrawn.
  const rng = scriptedRandom([0xFFFFFFFF, 4294967290, 13]);
  assert.equal(Core.secureRandomInt(10, rng), 3);
});

test('secureRandomInt validates its range', () => {
  assert.throws(() => Core.secureRandomInt(0));
  assert.throws(() => Core.secureRandomInt(1.5));
  assert.throws(() => Core.secureRandomInt(2 ** 33));
  assert.equal(Core.secureRandomInt(1), 0);
});

test('secureRandomInt is roughly uniform with real randomness', () => {
  const buckets = new Array(6).fill(0);
  const draws = 60000;
  for (let i = 0; i < draws; i++) buckets[Core.secureRandomInt(6)]++;
  for (const count of buckets) assert.ok(Math.abs(count - draws / 6) < draws / 6 * 0.1, `bucket ${count}`);
});

test('generateFromPool uses only pool characters and reports pool-based entropy', () => {
  const { value, entropyBits } = Core.generateFromPool(Core.CHARSETS.hex, 32);
  assert.equal(value.length, 32);
  assert.match(value, /^[0-9a-f]{32}$/);
  assert.equal(entropyBits, 128);
});

test('generateFromPool removes duplicate pool characters before computing entropy', () => {
  const { entropyBits } = Core.generateFromPool('aabb', 10);
  assert.equal(entropyBits, 10);
  assert.throws(() => Core.generateFromPool('', 10));
  assert.throws(() => Core.generateFromPool('abc', 0));
});

test('default password preset entropy is 20 * log2(88)', () => {
  const pool = Core.CHARSETS.upper + Core.CHARSETS.lower + Core.CHARSETS.numbers + Core.CHARSETS.symbols;
  const { entropyBits } = Core.generateFromPool(pool, 20);
  assert.ok(Math.abs(entropyBits - 20 * Math.log2(88)) < 1e-9);
});

test('generatePassphrase entropy depends on the word list, not the output length', () => {
  const words = Array.from({ length: 1024 }, (_, i) => `word${i}`);
  const { value, entropyBits } = Core.generatePassphrase(words, 5, '-');
  assert.equal(value.split('-').length, 5);
  assert.equal(entropyBits, 50);
  // Regression: the old meter rated a 5-word passphrase by its characters (about 200 bits).
  assert.equal(Core.strengthFromEntropy(entropyBits).label, 'Fair');
});

test('the shipped word list has no duplicates and gives about 50 bits for 5 words', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const source = fs.readFileSync(path.join(__dirname, '..', 'assets', 'js', 'app.js'), 'utf8');
  const list = source.match(/const WORDLIST = \[([\s\S]*?)\];/)[1].match(/'[^']+'/g).map((w) => w.slice(1, -1));
  assert.equal(new Set(list).size, list.length);
  const bits = Core.generatePassphrase(list, 5).entropyBits;
  assert.ok(bits > 49 && bits < 52, `${bits}`);
});

test('strengthFromEntropy thresholds', () => {
  assert.equal(Core.strengthFromEntropy(20).label, 'Weak');
  assert.equal(Core.strengthFromEntropy(40).label, 'Fair');
  assert.equal(Core.strengthFromEntropy(60).label, 'Good');
  assert.equal(Core.strengthFromEntropy(80).label, 'Strong');
  assert.equal(Core.strengthFromEntropy(128).label, 'Very Strong');
});

// ------------------------------------------------------------
// Speed test math
// ------------------------------------------------------------
test('summarizeLatency trims outliers and computes jitter in time order', () => {
  const samples = [20, 22, 20, 22, 20, 22, 20, 22, 20, 500];
  const { ping, jitter } = Core.summarizeLatency(samples);
  // The 500 ms outlier is dropped; the kept samples alternate by 2 ms.
  assert.equal(ping, 20);
  assert.equal(jitter, 2);
});

test('summarizeLatency jitter is zero for a steady connection', () => {
  assert.deepEqual(Core.summarizeLatency([15, 15, 15]), { ping: 15, jitter: 0 });
});

test('summarizeLatency handles few or no samples', () => {
  assert.deepEqual(Core.summarizeLatency([]), { ping: 0, jitter: 0 });
  assert.deepEqual(Core.summarizeLatency([30]), { ping: 30, jitter: 0 });
  assert.deepEqual(Core.summarizeLatency([10, 30]), { ping: 20, jitter: 20 });
  assert.deepEqual(Core.summarizeLatency([NaN, -1, 12]), { ping: 12, jitter: 0 });
});

test('throughputMbps ignores warm-up transfers', () => {
  const transfers = [
    { bytes: 10_000_000, endTime: 1500 },  // warm-up, ignored
    { bytes: 1_250_000, endTime: 2500 },
    { bytes: 1_250_000, endTime: 3000 },
  ];
  // 2.5 MB over 1 second = 20 Mbps
  assert.equal(Core.throughputMbps(transfers, 2000), 20);
  assert.equal(Core.throughputMbps([], 2000), 0);
  assert.equal(Core.throughputMbps([{ bytes: 1, endTime: 1000 }], 2000), 0);
});

test('gaugeDashOffset is clamped to the gauge range', () => {
  assert.equal(Core.gaugeDashOffset(0), Core.GAUGE_CIRCUMFERENCE);
  assert.equal(Core.gaugeDashOffset(300), 0);
  assert.equal(Core.gaugeDashOffset(10_000), 0);
  assert.equal(Core.gaugeDashOffset(-5), Core.GAUGE_CIRCUMFERENCE);
  assert.ok(Math.abs(Core.gaugeDashOffset(150) - Core.GAUGE_CIRCUMFERENCE / 2) < 1e-9);
});

// ------------------------------------------------------------
// Speed test timing (fake clock, no real network or timers)
// ------------------------------------------------------------
const flush = () => new Promise((resolve) => setImmediate(resolve));

/** Virtual clock: now() and timers share one fake time line that run() advances. */
function fakeClock() {
  let time = 0;
  let seq = 0;
  const pending = new Map();
  const timers = {
    setTimeout(fn, ms) { const id = ++seq; pending.set(id, { at: time + (ms || 0), fn }); return id; },
    clearTimeout(id) { pending.delete(id); },
  };
  return {
    now: () => time,
    timers,
    pendingCount: () => pending.size,
    /** Fire timers in order until none are left, letting promises settle between them. */
    async run() {
      for (let guard = 0; guard < 100000; guard++) {
        await flush();
        const next = [...pending.entries()].sort((a, b) => a[1].at - b[1].at || a[0] - b[0])[0];
        if (!next) return;
        pending.delete(next[0]);
        time = next[1].at;
        next[1].fn();
      }
      throw new Error('fake clock did not settle');
    },
  };
}

const after = (clock, ms, value) => new Promise((resolve) => clock.timers.setTimeout(() => resolve(value), ms));
const never = () => new Promise(() => {});

test('createDeadline aborts with a timeout reason at the deadline, not before', async () => {
  const clock = fakeClock();
  const d = Core.createDeadline(1000, { timers: clock.timers });
  let firedAt = null;
  d.signal.addEventListener('abort', () => { firedAt = clock.now(); });
  await clock.run();
  assert.equal(firedAt, 1000);
  assert.equal(Core.abortKind(d.signal), 'timeout');
});

test('createDeadline follows a parent cancel and clear() stops the timer', async () => {
  const clock = fakeClock();
  const parent = new AbortController();
  const d = Core.createDeadline(1000, { signal: parent.signal, timers: clock.timers });
  parent.abort(Core.speedAbortReason('cancelled'));
  assert.equal(Core.abortKind(d.signal), 'cancelled');
  assert.equal(clock.pendingCount(), 0);

  const quiet = Core.createDeadline(1000, { timers: clock.timers });
  quiet.clear();
  await clock.run();
  assert.equal(quiet.signal.aborted, false);
  assert.equal(Core.abortKind(new AbortController().signal), null);
});

test('raceAbort rejects on abort even when the work ignores the signal', async () => {
  const controller = new AbortController();
  const raced = Core.raceAbort(never(), controller.signal);
  controller.abort(Core.speedAbortReason('timeout'));
  await assert.rejects(raced, (err) => err.kind === 'timeout');
  assert.equal(await Core.raceAbort(Promise.resolve(7), controller.signal).catch((e) => e.kind), 'timeout');
  assert.equal(await Core.raceAbort(Promise.resolve(7), new AbortController().signal), 7);
});

test('runTransferPhase completes on a healthy connection and stops near the duration', async () => {
  const clock = fakeClock();
  const progress = [];
  const run = Core.runTransferPhase({
    transfer: (size) => after(clock, 250, size),
    now: clock.now, timers: clock.timers,
    durationMs: 12000, warmupMs: 2000, graceMs: 3000,
    onProgress: (pct) => progress.push(pct),
  });
  await clock.run();
  const result = await run;
  assert.equal(result.status, 'complete');
  assert.ok(result.mbps > 0);
  assert.ok(clock.now() >= 12000 && clock.now() < 12500, `ended at ${clock.now()}`);
  assert.equal(Math.max(...progress), 100);
  assert.equal(clock.pendingCount(), 0, 'deadline timer is cleared');
});

test('runTransferPhase ends a fully stalled phase at the hard deadline with no result', async () => {
  const clock = fakeClock();
  const seen = [];
  const run = Core.runTransferPhase({
    transfer: (size, id, signal) => { seen.push(signal); return never(); },
    now: clock.now, timers: clock.timers, durationMs: 12000, graceMs: 3000,
  });
  await clock.run();
  const result = await run;
  assert.equal(clock.now(), 15000);
  assert.equal(result.status, 'failed');
  assert.equal(result.mbps, null);
  assert.equal(seen.length, 4);
  assert.ok(seen.every((s) => s.aborted), 'in-flight requests are aborted');
});

test('runTransferPhase keeps completed transfers when the connection stalls mid-test', async () => {
  const clock = fakeClock();
  let calls = 0;
  const run = Core.runTransferPhase({
    transfer: (size) => (++calls <= 12 ? after(clock, 1000, size) : never()),
    now: clock.now, timers: clock.timers, durationMs: 12000, warmupMs: 2000, graceMs: 3000,
  });
  await clock.run();
  const result = await run;
  assert.equal(clock.now(), 15000);
  assert.equal(result.status, 'partial');
  assert.equal(result.transfers.length, 12);
  assert.ok(result.mbps > 0);
});

test('runTransferPhase stops at once on cancel and returns the speed so far', async () => {
  const clock = fakeClock();
  const controller = new AbortController();
  clock.timers.setTimeout(() => controller.abort(Core.speedAbortReason('cancelled')), 5000);
  const run = Core.runTransferPhase({
    transfer: (size) => after(clock, 250, size),
    signal: controller.signal, now: clock.now, timers: clock.timers,
  });
  await clock.run();
  const result = await run;
  assert.equal(result.status, 'cancelled');
  assert.ok(result.mbps > 0);
  assert.ok(result.transfers.every((t) => t.endTime <= 5000));
});

test('runTransferPhase reports a failed phase when every request errors', async () => {
  const clock = fakeClock();
  const run = Core.runTransferPhase({
    transfer: () => Promise.reject(new Error('HTTP 500')),
    now: clock.now, timers: clock.timers,
  });
  await clock.run();
  const result = await run;
  assert.equal(result.status, 'failed');
  assert.equal(result.mbps, null);
  assert.equal(clock.now(), 0, 'no waiting for the deadline after errors');
});

test('measureLatency skips a lost ping and keeps measuring', async () => {
  const clock = fakeClock();
  const run = Core.measureLatency({
    ping: (i) => (i === 3 ? never() : after(clock, 30)),
    count: 10, pingTimeoutMs: 2000, totalMs: 8000, now: clock.now, timers: clock.timers,
  });
  await clock.run();
  const result = await run;
  assert.equal(result.samples.length, 9);
  assert.equal(result.lost, 1);
  assert.ok(result.samples.every((s) => s === 30));
  assert.equal(result.status, 'complete');
});

test('measureLatency gives up at the phase deadline when every ping stalls', async () => {
  const clock = fakeClock();
  const run = Core.measureLatency({
    ping: never, count: 20, pingTimeoutMs: 2000, totalMs: 8000, now: clock.now, timers: clock.timers,
  });
  await clock.run();
  const result = await run;
  assert.equal(clock.now(), 8000);
  assert.equal(result.samples.length, 0);
  assert.equal(result.status, 'failed');
});

test('measureLatency honors a cancel that is already set', async () => {
  const controller = new AbortController();
  controller.abort(Core.speedAbortReason('cancelled'));
  let pings = 0;
  const result = await Core.measureLatency({ ping: () => { pings++; }, signal: controller.signal, timers: fakeClock().timers });
  assert.equal(pings, 0);
  assert.equal(result.status, 'cancelled');
});

test('summarizeSpeedRun explains complete, partial, cancelled and failed runs', () => {
  const ok = { status: 'complete', measured: true };
  assert.equal(Core.summarizeSpeedRun({ latency: ok, download: ok, upload: ok }).status, 'complete');

  const stalled = Core.summarizeSpeedRun({ latency: ok, download: { status: 'partial', measured: true }, upload: ok });
  assert.equal(stalled.status, 'partial');
  assert.match(stalled.message, /download test did not finish/);
  const both = Core.summarizeSpeedRun({ latency: ok, download: { status: 'partial', measured: true }, upload: { status: 'failed', measured: false } });
  assert.match(both.message, /download and upload tests did not finish/);

  const cancelled = Core.summarizeSpeedRun({ latency: ok, download: { status: 'cancelled', measured: false } });
  assert.equal(cancelled.status, 'cancelled');
  assert.match(cancelled.message, /measured so far/);
  assert.match(Core.summarizeSpeedRun({ latency: { status: 'cancelled', measured: false } }).message, /before anything was measured/);

  const failed = Core.summarizeSpeedRun({ latency: { status: 'failed', measured: false }, download: { status: 'failed', measured: false } });
  assert.equal(failed.status, 'failed');
  assert.match(failed.message, /Could not reach/);
});

// ------------------------------------------------------------
// IP geolocation parsers
// ------------------------------------------------------------
test('geo parsers normalize each provider', () => {
  const a = Core.parseIpapiCo({ ip: '203.0.113.7', org: 'Example ISP', asn: 'AS64500', version: 'IPv4', country_name: 'United States', country_code: 'US', city: 'Los Angeles', latitude: 34.05, longitude: -118.24, timezone: 'America/Los_Angeles' });
  assert.equal(a.country, 'United States');
  assert.equal(a.asn, 'AS64500');
  assert.equal(Core.parseIpapiCo({ error: true, reason: 'RateLimited' }), null);

  const b = Core.parseIpwhois({ success: true, ip: '203.0.113.7', type: 'IPv4', country: 'Canada', country_code: 'CA', connection: { asn: 64500, isp: 'ISP' }, security: { proxy: true }, timezone: { id: 'America/Toronto' } });
  assert.equal(b.asn, 'AS64500');
  assert.equal(b.proxy, true);
  assert.equal(b.timezone, 'America/Toronto');
  assert.equal(Core.parseIpwhois({ success: false }), null);

  const c = Core.parseFreeipapi({ ipAddress: '203.0.113.7', ipVersion: 4, countryName: 'Germany', countryCode: 'DE', isProxy: false });
  assert.equal(c.type, 'IPv4');
  assert.equal(Core.parseFreeipapi({}), null);
});

test('countryFlag builds regional indicators and rejects bad codes', () => {
  assert.equal(Core.countryFlag('us'), '\u{1F1FA}\u{1F1F8}');
  assert.equal(Core.countryFlag('USA'), '');
  assert.equal(Core.countryFlag('1A'), '');
  assert.equal(Core.countryFlag(undefined), '');
});

// ------------------------------------------------------------
// Report
// ------------------------------------------------------------
test('buildTextReport includes results and no password section without a password check', () => {
  const report = Core.buildTextReport({
    ip: '203.0.113.7',
    geo: { isp: 'ISP', org: 'Org', asn: 'AS1', type: 'IPv4', country: 'US', region: 'CA', city: 'LA', lat: 1, lng: 2, timezone: 'PT' },
    speed: { ping: 12.4, jitter: 1.25, download: 300.04, upload: null },
    breach: { email: null, password: null },
    scan: { domain: 'example.com', checks: [{ icon: 'pass', name: 'SPF Record', detail: 'ok' }, { icon: 'odd', name: 'X', detail: 'y' }] },
  }, new Date(0));
  assert.match(report, /IP: 203\.0\.113\.7/);
  assert.match(report, /Ping: 12 ms/);
  assert.match(report, /Upload: n\/a Mbps/);
  assert.match(report, /\[PASS\] SPF Record: ok/);
  assert.match(report, /\[\?\] X: y/);
  assert.ok(!/password/i.test(report));
});

test('buildTextReport handles an empty state', () => {
  const report = Core.buildTextReport({ speed: { ping: null } }, new Date(0));
  assert.match(report, /^=== NetScope Results ===/);
  assert.match(report, /Generated by NetScope$/);
});

// ------------------------------------------------------------
// Extended DNS and email checks
// ------------------------------------------------------------
test('evaluateDmarc warns when pct= applies the policy to only part of the mail', () => {
  const partial = Core.evaluateDmarc(['v=DMARC1; p=reject; pct=25']);
  assert.equal(partial.icon, 'warn');
  assert.match(partial.detail, /25%/);
  assert.equal(Core.evaluateDmarc(['v=DMARC1; p=reject; pct=100']).icon, 'pass');
});

test('evaluateMtaSts needs one record with a valid id', () => {
  assert.equal(Core.evaluateMtaSts([]).icon, 'info');
  assert.equal(Core.evaluateMtaSts(['v=STSv1; id=20260101T000000']).icon, 'pass');
  assert.equal(Core.evaluateMtaSts(['v=STSv1;']).icon, 'warn');
  assert.equal(Core.evaluateMtaSts(['v=STSv1; id=a', 'v=STSv1; id=b']).icon, 'warn');
});

test('evaluateTlsRpt needs a mailto or https rua', () => {
  assert.equal(Core.evaluateTlsRpt([]).icon, 'info');
  assert.equal(Core.evaluateTlsRpt(['v=TLSRPTv1; rua=mailto:tls@example.com']).icon, 'pass');
  assert.equal(Core.evaluateTlsRpt(['v=TLSRPTv1; rua=ftp://x']).icon, 'warn');
});

test('evaluateBimi depends on an enforced DMARC policy and an https logo', () => {
  const enforced = { icon: 'pass' };
  assert.equal(Core.evaluateBimi([], enforced).icon, 'info');
  assert.equal(Core.evaluateBimi(['v=BIMI1; l=https://example.com/logo.svg'], enforced).icon, 'pass');
  assert.equal(Core.evaluateBimi(['v=BIMI1; l=http://example.com/logo.svg'], enforced).icon, 'warn');
  assert.equal(Core.evaluateBimi(['v=BIMI1; l=https://example.com/logo.svg'], { icon: 'warn' }).icon, 'warn');
});

test('evaluateDkim lists every selector found and treats a miss as information', () => {
  assert.match(Core.evaluateDkim(['google', 'k1']).detail, /selectors: google, k1/);
  assert.equal(Core.evaluateDkim([]).icon, 'info');
});

test('summarizeChecks gives one verdict from the worst result', () => {
  assert.equal(Core.summarizeChecks([{ icon: 'pass' }, { icon: 'info' }]).verdict, 'good');
  assert.equal(Core.summarizeChecks([{ icon: 'pass' }, { icon: 'warn' }]).verdict, 'needs-attention');
  const risk = Core.summarizeChecks([{ icon: 'fail' }, { icon: 'warn' }, { icon: 'pass' }]);
  assert.deepEqual([risk.verdict, risk.fail, risk.warn, risk.pass], ['at-risk', 1, 1, 1]);
});

function fakeDoh(zone, { fail = [] } = {}) {
  const calls = [];
  const doh = async (name, type, extra = '') => {
    calls.push(`${name} ${type}${extra}`);
    if (fail.includes(`${name} ${type}`)) throw new Error('network');
    if (zone.nxdomain) return { Status: 3 };
    const answers = (zone[`${name} ${type}`] || []).map((data) => ({ type: { A: 1, NS: 2, MX: 15, TXT: 16, AAAA: 28 }[type], data, TTL: 300 }));
    return { Status: 0, AD: Boolean(zone.ad && extra), Answer: answers };
  };
  return { doh, calls };
}

test('scanDomain grades a well configured domain and probes every DKIM selector in one pass', async () => {
  const { doh, calls } = fakeDoh({
    ad: true,
    'example.com A': ['203.0.113.10'],
    'example.com MX': ['10 mx.example.com.'],
    'example.com NS': ['ns1.example.com.'],
    'example.com TXT': ['"v=spf1 mx -all"'],
    '_dmarc.example.com TXT': ['"v=DMARC1; p=reject"'],
    '_mta-sts.example.com TXT': ['"v=STSv1; id=1"'],
    '_smtp._tls.example.com TXT': ['"v=TLSRPTv1; rua=mailto:t@example.com"'],
    'default._bimi.example.com TXT': ['"v=BIMI1; l=https://example.com/l.svg; a=https://example.com/c.pem"'],
    'google._domainkey.example.com TXT': ['"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"'],
  });
  const result = await Core.scanDomain('example.com', doh);
  assert.equal(result.status, 'ok');
  assert.equal(result.records.length, 3);
  const byName = Object.fromEntries(result.checks.map((c) => [c.name, c]));
  for (const name of ['SPF Record', 'DMARC Policy', 'DKIM', 'DNSSEC', 'MTA-STS', 'TLS Reporting', 'BIMI']) {
    assert.equal(byName[name].icon, 'pass', name);
    assert.ok(byName[name].explain, `${name} has a plain-language explanation`);
  }
  assert.match(byName.DKIM.detail, /google/);
  assert.equal(calls.filter((c) => c.includes('._domainkey.')).length, Core.DKIM_SELECTORS.length);
  assert.equal(Core.summarizeChecks(result.checks).verdict, 'good');
});

test('scanDomain reports a domain that does not exist instead of grading it', async () => {
  const { doh } = fakeDoh({ nxdomain: true });
  const result = await Core.scanDomain('no-such-name.example', doh);
  assert.equal(result.status, 'nxdomain');
  assert.equal(result.checks.length, 0);
});

test('scanDomain reports an error when every lookup fails, never a clean result', async () => {
  const result = await Core.scanDomain('example.com', async () => { throw new Error('offline'); });
  assert.equal(result.status, 'error');
  assert.equal(result.checks.length, 0);
});

test('scanDomain says a failed lookup could not be checked rather than calling it missing', async () => {
  const { doh } = fakeDoh({ 'example.com A': ['203.0.113.10'] }, { fail: ['_dmarc.example.com TXT'] });
  const result = await Core.scanDomain('example.com', doh);
  const dmarc = result.checks.find((c) => c.name === 'DMARC Policy');
  assert.equal(dmarc.icon, 'warn');
  assert.match(dmarc.detail, /Could not look up DMARC/);
});

test('buildTextReport adds the scan verdict and the email result', () => {
  const report = Core.buildTextReport({
    breach: { email: { email: 'me@example.com', status: 'found', count: 2 }, password: null },
    scan: { domain: 'example.com', checks: [{ icon: 'fail', name: 'SPF Record', detail: 'none' }] },
  }, new Date(0));
  assert.match(report, /Email me@example\.com: found in 2 breaches/);
  assert.match(report, /Overall: At risk \(0 pass, 0 warn, 1 fail, 0 info\)/);
  assert.ok(!/Password Check/.test(report));
});

test('estimatePasswordStrength scores by character classes and length, and breached means weak', () => {
  assert.deepEqual(Core.estimatePasswordStrength(''), { level: 'weak', label: 'Weak', score: 1, outOf: 5 });
  assert.equal(Core.estimatePasswordStrength('password').score, 1);
  assert.equal(Core.estimatePasswordStrength('aaaaaaaaaaaaaaaa').score, 1, 'repeats count half');
  assert.equal(Core.estimatePasswordStrength('Tr0ub4dor&3').score, 3);
  assert.equal(Core.estimatePasswordStrength('correct-horse-battery-staple-Z9').score, 5);
  assert.equal(Core.estimatePasswordStrength('correct-horse-battery-staple-Z9', { breached: true }).score, 1);
});

test('passwordCheckSummary keeps only found or not found and the strength score', () => {
  const password = 'hunter2-Example!';
  const summary = Core.passwordCheckSummary(password, 12345);
  assert.deepEqual(summary, { found: true, strength: { label: 'Weak', score: 1, outOf: 5 } });
  assert.deepEqual(Object.keys(summary).sort(), ['found', 'strength']);
  const clean = Core.passwordCheckSummary(password, 0);
  assert.equal(clean.found, false);
  assert.equal(clean.strength.score, 5);
  assert.ok(!JSON.stringify(summary).includes(password));
  assert.ok(!JSON.stringify(summary).includes('12345'));
});

test('buildTextReport password section shows breach status and strength only', async () => {
  const password = 'hunter2-Example!';
  const fullHash = await Core.sha1Hex(password);
  const breached = Core.buildTextReport({ breach: { password: Core.passwordCheckSummary(password, 52256179) } }, new Date(0));
  assert.match(breached, /--- Password Check ---\nBreached: yes, found in known breaches\nStrength: Weak \(1 of 5\)/);

  const clean = Core.buildTextReport({ breach: { password: Core.passwordCheckSummary(password, 0) } }, new Date(0));
  assert.match(clean, /Breached: no, not found in known breaches\nStrength: Very Strong \(5 of 5\)/);

  for (const report of [breached, clean]) {
    assert.ok(!report.includes(password), 'password must not appear');
    assert.ok(!report.toUpperCase().includes(fullHash), 'full hash must not appear');
    assert.ok(!report.toUpperCase().includes(fullHash.slice(0, 5)), 'hash prefix must not appear');
    assert.ok(!/52,?256,?179/.test(report), 'breach count must not appear');
  }
});

test('buildTextReport ignores anything but the safe password fields, even if state is polluted', async () => {
  const password = 'hunter2-Example!';
  const fullHash = await Core.sha1Hex(password);
  const report = Core.buildTextReport({
    breach: { password: { found: false, strength: { label: password, score: 2 }, password, hash: fullHash, count: 9876 } },
  }, new Date(0));
  assert.match(report, /Breached: no, not found in known breaches\nStrength: Fair \(2 of 5\)/);
  assert.ok(!report.includes(password));
  assert.ok(!report.includes(fullHash));
  assert.ok(!report.includes('9876'));
  // A bad score is dropped rather than printed.
  const bad = Core.buildTextReport({ breach: { password: { found: true, strength: { score: 'x' } } } }, new Date(0));
  assert.ok(!/Strength:/.test(bad));
  assert.match(bad, /Breached: yes/);
  // Old-shape state without a found flag adds nothing.
  assert.ok(!/Password Check/.test(Core.buildTextReport({ breach: { password: { count: 3 } } }, new Date(0))));
});

// ------------------------------------------------------------
// Network helpers
// ------------------------------------------------------------
test('fetchWithTimeout aborts a request that never answers', async () => {
  const hanging = (url, init) => new Promise((resolve, reject) => {
    init.signal.addEventListener('abort', () => reject(new Error('aborted')));
  });
  await assert.rejects(
    Core.fetchWithTimeout('https://example.com', {}, { fetchImpl: hanging, timeoutMs: 20 }),
    (err) => err.name === 'TimeoutError' && /20 ms/.test(err.message)
  );
});

test('fetchWithTimeout passes options through and returns the response', async () => {
  const { calls, fetchImpl } = recordingFetch(() => fakeResponse({ body: 'ok' }));
  const response = await Core.fetchWithTimeout('https://example.com/x', { referrerPolicy: 'no-referrer' }, { fetchImpl, timeoutMs: 1000 });
  assert.equal(await response.text(), 'ok');
  assert.equal(calls[0].init.referrerPolicy, 'no-referrer');
  assert.ok(calls[0].init.signal, 'an abort signal is attached');
});

test('fetchWithTimeout rethrows ordinary network errors unchanged', async () => {
  await assert.rejects(
    Core.fetchWithTimeout('https://example.com', {}, { fetchImpl: async () => { throw new TypeError('Failed to fetch'); } }),
    (err) => err instanceof TypeError
  );
});

test('isIpAddress accepts IPv4 and IPv6 and rejects anything else', () => {
  for (const ok of ['203.0.113.7', '2001:db8::1', '::1', '2001:0db8:0000:0000:0000:ff00:0042:8329', '::ffff:192.0.2.1']) assert.ok(Core.isIpAddress(ok), ok);
  for (const bad of ['', 'localhost', '256.1.1.1', '<script>', '2001:db8::1::2', '1:2:3:4:5:6:7:8:9:a:b:c:d:e:f:0:1:2:3:4:5:6:7']) assert.ok(!Core.isIpAddress(bad), bad);
});

test('scanDomain recognizes a null MX as a domain that does not accept mail', async () => {
  const { doh } = fakeDoh({ 'example.com A': ['203.0.113.10'], 'example.com MX': ['0 .'] });
  const result = await Core.scanDomain('example.com', doh);
  assert.match(result.checks.find((c) => c.name === 'Mail Servers').detail, /does not accept email/);
});

// ------------------------------------------------------------
// Domain grade and fix guidance
// ------------------------------------------------------------
test('gradeChecks maps the score to a letter and lists where points were lost', () => {
  const perfect = Core.gradeChecks([{ icon: 'pass', name: 'SPF Record' }, { icon: 'pass', name: 'DMARC Policy' }, { icon: 'info', name: 'MTA-STS' }]);
  assert.deepEqual({ grade: perfect.grade, score: perfect.score, incomplete: perfect.incomplete }, { grade: 'A', score: 100, incomplete: false });
  assert.deepEqual(perfect.deductions, []);

  const monitoring = Core.gradeChecks([{ icon: 'pass', name: 'SPF Record' }, { icon: 'warn', name: 'DMARC Policy' }]);
  assert.equal(monitoring.score, 85);
  assert.equal(monitoring.grade, 'B');
  assert.deepEqual(monitoring.deductions, [{ name: 'DMARC Policy', points: 15 }]);

  assert.equal(Core.gradeChecks([{ icon: 'warn', name: 'DMARC Policy' }, { icon: 'warn', name: 'DNSSEC' }]).grade, 'C');
  assert.equal(Core.gradeChecks([{ icon: 'fail', name: 'SPF Record' }, { icon: 'warn', name: 'DNSSEC' }]).grade, 'D');
  const open = Core.gradeChecks([{ icon: 'fail', name: 'SPF Record' }, { icon: 'fail', name: 'DMARC Policy' }, { icon: 'warn', name: 'DNSSEC' }]);
  assert.equal(open.grade, 'F');
  assert.equal(open.score, 25);
  assert.ok(open.summary.length > 0);
});

test('gradeChecks never goes below zero and handles an empty list', () => {
  const all = ['SPF Record', 'DMARC Policy', 'DNSSEC', 'DKIM', 'MTA-STS', 'TLS Reporting', 'BIMI'].map((name) => ({ icon: 'fail', name }));
  assert.equal(Core.gradeChecks([...all, ...all]).score, 0);
  assert.equal(Core.gradeChecks([]).grade, 'A');
  assert.equal(Core.gradeChecks(null).score, 100);
});

test('gradeChecks ignores browser checks and does not punish a lookup that failed', () => {
  const graded = Core.gradeChecks([
    { icon: 'pass', name: 'SPF Record' },
    { icon: 'warn', name: 'DMARC Policy', unknown: true },
    { icon: 'warn', name: 'WebRTC Leak' },
    { icon: 'fail', name: 'Your Connection' },
  ]);
  assert.equal(graded.score, 100);
  assert.equal(graded.incomplete, true);
});

test('every problem an evaluator reports comes with a way to fix it', () => {
  const problems = [
    Core.evaluateSpf([]),
    Core.evaluateSpf(['v=spf1 -all', 'v=spf1 mx -all']),
    Core.evaluateSpf(['v=spf1 +all']),
    Core.evaluateSpf(['v=spf1 mx ?all']),
    Core.evaluateDmarc([]),
    Core.evaluateDmarc(['v=DMARC1; p=reject', 'v=DMARC1; p=none']),
    Core.evaluateDmarc(['v=DMARC1; p=quarantine; pct=20']),
    Core.evaluateDmarc(['v=DMARC1; p=none']),
    Core.evaluateDmarc(['v=DMARC1; rua=mailto:d@example.com']),
    Core.evaluateDnssec({ AD: false }),
    Core.evaluateMtaSts([]),
    Core.evaluateMtaSts(['v=STSv1; id=1', 'v=STSv1; id=2']),
    Core.evaluateMtaSts(['v=STSv1; id=!!']),
    Core.evaluateTlsRpt([]),
    Core.evaluateTlsRpt(['v=TLSRPTv1; rua=nobody']),
    Core.evaluateBimi(['v=BIMI1; l=http://example.com/l.svg']),
    Core.evaluateBimi(['v=BIMI1; l=https://example.com/l.svg'], { icon: 'warn' }),
    Core.evaluateDkim([]),
  ];
  for (const check of problems) {
    assert.notEqual(check.icon, 'pass', check.detail);
    assert.ok(typeof check.fix === 'string' && check.fix.length > 20, `${check.name}: ${check.detail} has no fix`);
    assert.ok(!/[.]$/.test(check.fix), 'fix text has no trailing period, like detail text');
  }
  for (const check of [Core.evaluateSpf(['v=spf1 mx -all']), Core.evaluateDmarc(['v=DMARC1; p=reject']), Core.evaluateDnssec({ AD: true })]) {
    assert.equal(check.icon, 'pass');
    assert.equal(check.fix, undefined);
  }
});

test('scanDomain marks failed lookups unknown so the grade is incomplete, not worse', async () => {
  const { doh } = fakeDoh({ ad: true, 'example.com A': ['203.0.113.10'], 'example.com TXT': ['"v=spf1 -all"'] }, { fail: ['_dmarc.example.com TXT'] });
  const result = await Core.scanDomain('example.com', doh);
  assert.equal(result.checks.find((c) => c.name === 'DMARC Policy').unknown, true);
  const grade = Core.gradeChecks(result.checks);
  assert.equal(grade.incomplete, true);
  assert.equal(grade.score, 100);
});

test('scanDomain gives an unprotected domain an F with fixes for SPF and DMARC', async () => {
  const { doh } = fakeDoh({ 'example.com A': ['203.0.113.10'] });
  const result = await Core.scanDomain('example.com', doh);
  const grade = Core.gradeChecks(result.checks);
  assert.equal(grade.grade, 'F');
  assert.match(result.checks.find((c) => c.name === 'SPF Record').fix, /v=spf1/);
  assert.match(result.checks.find((c) => c.name === 'DMARC Policy').fix, /_dmarc/);
});

test('buildTextReport includes the grade and how to fix each problem', () => {
  const report = Core.buildTextReport({
    scan: { domain: 'example.com', checks: [Core.evaluateSpf([]), Core.evaluateDmarc(['v=DMARC1; p=reject']), { icon: 'pass', name: 'Your Connection', detail: 'HTTPS' }] },
  }, new Date(0));
  assert.match(report, /Grade: C \(70 of 100\)\. Partly protected/);
  assert.match(report, /\[FAIL\] SPF Record: No SPF record found[^\n]*\n {7}How to fix: Publish one TXT record/);
  assert.equal(report.match(/How to fix:/g).length, 1);
});

// ------------------------------------------------------------
// Subnet calculator
// ------------------------------------------------------------
const rowMap = (result) => Object.fromEntries(result.rows.map((r) => [r.label, r.value]));

test('calculateSubnet works out an IPv4 /24 from a host address', () => {
  const result = Core.calculateSubnet(' 192.168.1.10/24 ');
  assert.equal(result.ok, true);
  assert.equal(result.cidr, '192.168.1.0/24');
  assert.deepEqual(rowMap(result), {
    Network: '192.168.1.0/24', 'Subnet mask': '255.255.255.0', 'Wildcard mask': '0.0.0.255',
    Broadcast: '192.168.1.255', 'First usable': '192.168.1.1', 'Last usable': '192.168.1.254',
    'Usable hosts': '254', 'Total addresses': '256', 'Address type': 'Private (RFC 1918)',
  });
});

test('calculateSubnet accepts a dotted mask after a space or a slash', () => {
  for (const input of ['10.0.0.1 255.255.252.0', '10.0.0.1/255.255.252.0', '10.0.0.1   255.255.252.0']) {
    const rows = rowMap(Core.calculateSubnet(input));
    assert.equal(rows.Network, '10.0.0.0/22', input);
    assert.equal(rows.Broadcast, '10.0.3.255');
    assert.equal(rows['Usable hosts'], '1,022');
  }
  assert.match(Core.calculateSubnet('10.0.0.1 255.0.255.0').error, /not a valid subnet mask/);
  assert.equal(Core.maskToPrefix('255.255.255.255'), 32);
  assert.equal(Core.maskToPrefix('0.0.0.0'), 0);
  assert.equal(Core.maskToPrefix('255.255.255.128'), 25);
  assert.equal(Core.maskToPrefix('255.255.255.1'), null);
});

test('calculateSubnet handles the edges: /0, /31, /32 and the top of the address space', () => {
  const all = rowMap(Core.calculateSubnet('0.0.0.0/0'));
  assert.equal(all['Subnet mask'], '0.0.0.0');
  assert.equal(all.Broadcast, '255.255.255.255');
  assert.equal(all['Total addresses'], '4,294,967,296');

  const link = Core.calculateSubnet('10.1.2.3/31');
  assert.deepEqual([rowMap(link)['First usable'], rowMap(link)['Last usable'], rowMap(link)['Usable hosts'], rowMap(link).Broadcast], ['10.1.2.2', '10.1.2.3', '2', 'None']);
  assert.match(link.note, /RFC 3021/);

  const host = Core.calculateSubnet('255.255.255.255/32');
  assert.equal(rowMap(host).Network, '255.255.255.255/32');
  assert.equal(rowMap(host)['Usable hosts'], '1');

  const top = rowMap(Core.calculateSubnet('255.255.255.200/25'));
  assert.equal(top.Network, '255.255.255.128/25');
  assert.equal(top.Broadcast, '255.255.255.255');
  assert.equal(top['Subnet mask'], '255.255.255.128');

  assert.match(Core.calculateSubnet('192.168.1.0/24').note, /network address/);
  assert.match(Core.calculateSubnet('192.168.1.255/24').note, /broadcast address/);
});

test('calculateSubnet labels special IPv4 ranges', () => {
  const type = (input) => rowMap(Core.calculateSubnet(input))['Address type'];
  assert.equal(type('8.8.8.8/32'), 'Public');
  assert.equal(type('172.31.255.1/16'), 'Private (RFC 1918)');
  assert.equal(type('172.32.0.1/16'), 'Public');
  assert.equal(type('100.64.0.1/10'), 'Carrier-grade NAT (RFC 6598)');
  assert.equal(type('169.254.10.1/16'), 'Link-local (RFC 3927)');
  assert.equal(type('203.0.113.7/24'), 'Documentation (RFC 5737)');
  assert.equal(type('224.0.0.251/4'), 'Multicast');
  assert.equal(type('127.0.0.1/8'), 'Loopback');
});

test('calculateSubnet handles IPv6 with BigInt math and canonical text', () => {
  const doc = Core.calculateSubnet('2001:0DB8:0000:0000:0000:0000:0000:0001/48');
  assert.equal(doc.version, 6);
  assert.equal(doc.address, '2001:db8::1');
  assert.deepEqual(rowMap(doc), {
    Network: '2001:db8::/48', 'First address': '2001:db8::', 'Last address': '2001:db8:0:ffff:ffff:ffff:ffff:ffff',
    'Total addresses': '2^80', '/64 networks': '65,536', 'Address type': 'Documentation (RFC 3849)',
  });
  const lan = rowMap(Core.calculateSubnet('fe80::1/64'));
  assert.equal(lan['Total addresses'], '18,446,744,073,709,551,616');
  assert.equal(lan['Address type'], 'Link-local');
  assert.equal(rowMap(Core.calculateSubnet('fd12:3456:789a::1/48'))['Address type'], 'Unique local (RFC 4193)');
  assert.equal(rowMap(Core.calculateSubnet('2606:4700::1111/32'))['Address type'], 'Global unicast');
  assert.equal(rowMap(Core.calculateSubnet('::1/128'))['Address type'], 'Loopback');
  assert.equal(rowMap(Core.calculateSubnet('::/0'))['Last address'], 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff');
  assert.equal(rowMap(Core.calculateSubnet('::ffff:192.0.2.1/96')).Network, '::ffff:0:0/96');
  assert.match(Core.calculateSubnet('2001:db8::/80').note, /SLAAC/);
});

test('IPv6 text round-trips and compresses the first longest zero run', () => {
  const cases = { '2001:db8:0:0:1:0:0:1': '2001:db8::1:0:0:1', '0:0:0:0:0:0:0:0': '::', '1:0:0:0:0:0:0:0': '1::', '2001:db8:0:1:1:1:1:1': '2001:db8:0:1:1:1:1:1', 'FE80::A': 'fe80::a' };
  for (const [input, expected] of Object.entries(cases)) {
    assert.equal(Core.bigIntToIpv6(Core.ipv6ToBigInt(input)), expected, input);
  }
  for (const bad of ['1::2::3', ':::', '12345::', '1:2:3:4:5:6:7', '1:2:3:4:5:6:7:8:9', 'g::1', '::1.2.3.999', '1:2:3:4:5:6:7::8']) {
    assert.equal(Core.ipv6ToBigInt(bad), null, bad);
  }
});

test('calculateSubnet explains bad input instead of guessing', () => {
  const error = (input) => { const r = Core.calculateSubnet(input); assert.equal(r.ok, false, String(input)); return r.error; };
  assert.match(error(''), /Enter an address/);
  assert.match(error(null), /Enter an address/);
  assert.match(error('192.168.1.10'), /Add a prefix length or mask/);
  assert.match(error('192.168.1.10/33'), /0 to 32/);
  assert.match(error('192.168.1.10/-1'), /0 to 32/);
  assert.match(error('192.168.1.10/2.5'), /0 to 32/);
  assert.match(error('192.168.1.256/24'), /not a valid IPv4 or IPv6 address/);
  assert.match(error('10.0.0.0/8/9'), /one slash/);
  assert.match(error('10.0.0.0 255.0.0.0 extra'), /one address/);
  assert.match(error('2001:db8::/129'), /0 to 128/);
  assert.match(error('2001:db8::'), /Add a prefix length/);
  assert.match(error('2001:db8:: 255.255.0.0'), /not a dotted mask/);
  assert.match(error('<b>x/24'), /not a valid/);
  assert.match(error('1'.repeat(200)), /too long/);
});

// ------------------------------------------------------------
// JWT inspector
// ------------------------------------------------------------
const b64url = (value) => Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64url');
const makeJwt = (header, payload, signature = 'c2lnbmF0dXJl') => `${b64url(header)}.${b64url(payload)}.${signature}`;
const NOW = Date.UTC(2026, 0, 1, 12, 0, 0);
const nowSeconds = NOW / 1000;
const finding = (result, name) => result.findings.filter((f) => f.name === name);

test('inspectJwt decodes the header and payload and explains the time claims', () => {
  const token = makeJwt({ alg: 'RS256', typ: 'JWT', kid: 'demo' }, { iss: 'https://issuer.example', sub: 'demo-user', iat: nowSeconds - 600, exp: nowSeconds + 3000, name: 'Zoë Exämple' });
  const result = Core.inspectJwt(`Bearer ${token}\n`, NOW);
  assert.equal(result.ok, true);
  assert.equal(result.algorithm, 'RS256');
  assert.equal(result.status, 'active');
  assert.deepEqual(result.header, { alg: 'RS256', typ: 'JWT', kid: 'demo' });
  assert.equal(result.payload.name, 'Zoë Exämple', 'UTF-8 claims decode correctly');
  assert.equal(finding(result, 'Algorithm')[0].icon, 'pass');
  assert.match(finding(result, 'Expires')[0].detail, /Expires in 50 minutes/);
  const exp = result.claims.find((c) => c.key === 'exp');
  assert.equal(exp.label, 'Expires');
  assert.equal(exp.value, `2026-01-01T12:50:00.000Z (${nowSeconds + 3000})`);
  assert.ok(finding(result, 'Signature').some((f) => /Not verified/.test(f.detail)), 'always says the signature was not verified');
});

test('inspectJwt flags unsigned, expired, not yet valid and never-expiring tokens', () => {
  const none = Core.inspectJwt(makeJwt({ alg: 'none' }, { sub: 'x', exp: nowSeconds + 60 }, ''), NOW);
  assert.equal(finding(none, 'Algorithm')[0].icon, 'fail');
  assert.match(finding(none, 'Algorithm')[0].detail, /unsigned/);
  assert.equal(finding(Core.inspectJwt(makeJwt({ alg: 'NoNe' }, {}, ''), NOW), 'Algorithm')[0].icon, 'fail', 'alg none is matched in any case');

  const expired = Core.inspectJwt(makeJwt({ alg: 'ES256' }, { exp: nowSeconds - 7200 }), NOW);
  assert.equal(expired.status, 'expired');
  assert.match(finding(expired, 'Expires')[0].detail, /Expired 2 hours ago/);

  const early = Core.inspectJwt(makeJwt({ alg: 'ES256' }, { nbf: nowSeconds + 90, exp: nowSeconds + 900 }), NOW);
  assert.equal(early.status, 'not-yet-valid');
  assert.match(finding(early, 'Not valid before')[0].detail, /another 1 minute/);

  const forever = Core.inspectJwt(makeJwt({ alg: 'ES256' }, { sub: 'x' }), NOW);
  assert.equal(forever.status, 'no-expiry');
  assert.equal(finding(forever, 'Expires')[0].icon, 'warn');
});

test('inspectJwt points out shared secrets, stripped signatures, key hints, long lifetimes and bad time values', () => {
  const hs = Core.inspectJwt(makeJwt({ alg: 'HS256' }, { iat: nowSeconds, exp: nowSeconds + 30 * 86400 }), NOW);
  assert.equal(finding(hs, 'Algorithm')[0].icon, 'info');
  assert.match(finding(hs, 'Lifetime')[0].detail, /30 days/);

  const stripped = Core.inspectJwt(makeJwt({ alg: 'RS256' }, { exp: nowSeconds + 60 }, ''), NOW);
  assert.ok(finding(stripped, 'Signature').some((f) => f.icon === 'fail'));

  const hinted = Core.inspectJwt(makeJwt({ alg: 'RS256', jku: 'https://attacker.example/keys' }, { exp: nowSeconds + 60 }), NOW);
  assert.equal(finding(hinted, 'Key hint in header')[0].icon, 'warn');

  const odd = Core.inspectJwt(makeJwt({ alg: 'RS256' }, { exp: 'tomorrow', iat: nowSeconds + 3600 }), NOW);
  assert.equal(odd.status, 'no-expiry');
  assert.match(finding(odd, 'Expires')[0].detail, /should be a number/);
  assert.match(finding(odd, 'Issued at')[0].detail, /in the future/);

  assert.equal(finding(Core.inspectJwt(makeJwt({ typ: 'JWT' }, { exp: nowSeconds + 60 }), NOW), 'Algorithm')[0].icon, 'fail');
});

test('inspectJwt rejects malformed input with a specific message', () => {
  const error = (input) => { const r = Core.inspectJwt(input, NOW); assert.equal(r.ok, false); return r.error; };
  assert.match(error(''), /Paste a token/);
  assert.match(error(undefined), /Paste a token/);
  assert.match(error('abc.def'), /three parts[^]*This has 2/);
  assert.match(error('a.b.c.d.e'), /encrypted token/);
  assert.match(error('a b.c.d'), /no spaces/);
  assert.match(error('!!!.e30.sig'), /header is not valid base64url/);
  assert.match(error(`${b64url('not json')}.e30.sig`), /header is not valid JSON/);
  assert.match(error(`${b64url('[1]')}.e30.sig`), /header is not a JSON object/);
  assert.match(error(`${b64url({ alg: 'RS256' })}.${b64url('"text"')}.sig`), /payload is not a JSON object/);
  assert.match(error(`${b64url({ alg: 'RS256' })}.${Buffer.from([0xff, 0xfe]).toString('base64url')}.sig`), /payload is not valid base64url/);
  assert.match(error(`${b64url({ alg: 'RS256' })}.e30.si+g`), /signature is not valid base64url/);
  assert.match(error('a'.repeat(20000)), /too long/);
});

test('inspectJwt keeps hostile claim text as data', () => {
  const hostile = '<img src=x onerror=alert(1)>';
  const result = Core.inspectJwt(makeJwt({ alg: 'RS256' }, { sub: hostile, exp: nowSeconds + 60, nested: { a: [1, 2] } }), NOW);
  assert.equal(result.claims.find((c) => c.key === 'sub').value, hostile);
  assert.equal(result.claims.find((c) => c.key === 'nested').value, '{"a":[1,2]}');
  assert.ok(!Core.escapeHtml(result.claims[0].value).includes('<'));
});

test('describeDuration picks the largest whole unit', () => {
  assert.equal(Core.describeDuration(999), '1 second');
  assert.equal(Core.describeDuration(45000), '45 seconds');
  assert.equal(Core.describeDuration(60000), '1 minute');
  assert.equal(Core.describeDuration(-7200000), '2 hours');
  assert.equal(Core.describeDuration(3 * 86400000), '3 days');
  assert.equal(Core.describeDuration(800 * 86400000), '2 years');
});

test('jwtReportSummary and the report never carry the token or its claims', () => {
  const secretClaim = 'customer-7f3a-private';
  const token = makeJwt({ alg: 'none', kid: 'key-id-123' }, { sub: secretClaim, email: 'person@example.com' }, '');
  const result = Core.inspectJwt(token, NOW);
  const summary = Core.jwtReportSummary(result);
  assert.deepEqual(summary, { algorithm: 'none', status: 'no-expiry', findings: [{ icon: 'fail', name: 'Algorithm' }, { icon: 'warn', name: 'Expires' }] });
  assert.equal(Core.jwtReportSummary({ ok: false, error: 'x' }), null);
  assert.equal(Core.jwtReportSummary(Core.inspectJwt(makeJwt({ alg: '<b>weird alg value</b>' }, {}), NOW)).algorithm, 'other');

  const report = Core.buildTextReport({ jwt: summary }, new Date(0));
  assert.match(report, /--- Token Check ---\nAlgorithm: none\nStatus: No expiry set\n\[FAIL\] Algorithm\n\[WARN\] Expires\nSignature: not verified/);
  for (const leak of [secretClaim, 'person@example.com', 'key-id-123', ...token.split('.').filter(Boolean)]) {
    assert.ok(!report.includes(leak), `report leaked ${leak}`);
    assert.ok(!JSON.stringify(summary).includes(leak), `summary leaked ${leak}`);
  }
});

test('buildTextReport adds a subnet section and skips failed calculations', () => {
  const report = Core.buildTextReport({ subnet: Core.calculateSubnet('10.20.30.40/20') }, new Date(0));
  assert.match(report, /--- Subnet: 10\.20\.16\.0\/20 ---\nNetwork: 10\.20\.16\.0\/20\nSubnet mask: 255\.255\.240\.0/);
  assert.match(report, /Usable hosts: 4,094/);
  assert.ok(!/Subnet/.test(Core.buildTextReport({ subnet: Core.calculateSubnet('nope') }, new Date(0))));
  assert.ok(!/Token Check/.test(Core.buildTextReport({ jwt: null }, new Date(0))));
});
