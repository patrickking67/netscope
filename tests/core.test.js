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
test('buildTextReport includes results and never includes a password', () => {
  const report = Core.buildTextReport({
    ip: '203.0.113.7',
    geo: { isp: 'ISP', org: 'Org', asn: 'AS1', type: 'IPv4', country: 'US', region: 'CA', city: 'LA', lat: 1, lng: 2, timezone: 'PT' },
    speed: { ping: 12.4, jitter: 1.25, download: 300.04, upload: null },
    breach: { email: null, password: { count: 3 } },
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
