/* ===== NetScope core logic =====
 * Pure functions with no DOM access. Loaded as a classic script in the
 * browser (exposed as window.NetScopeCore) and with require() in Node tests.
 * Anything that talks to the network takes its fetch function as an argument
 * so tests can inspect exactly what would leave the browser.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  } else {
    root.NetScopeCore = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // ============================================================
  // HTML ESCAPING
  // ============================================================
  const HTML_ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

  /** Escape a value for use in HTML text or a quoted attribute. */
  function escapeHtml(value) {
    if (value === null || value === undefined) return '';
    return String(value).replace(/[&<>"']/g, (ch) => HTML_ESCAPES[ch]);
  }

  // ============================================================
  // PASSWORD BREACH CHECK (HIBP Pwned Passwords, k-anonymity)
  // ============================================================
  const PWNED_RANGE_ENDPOINT = 'https://api.pwnedpasswords.com/range/';
  const PWNED_PREFIX_LENGTH = 5;

  function defaultSubtle() {
    return globalThis.crypto && globalThis.crypto.subtle;
  }

  /** SHA-1 of a UTF-8 string as 40 uppercase hex characters. */
  async function sha1Hex(text, subtle = defaultSubtle()) {
    if (!subtle) throw new Error('Web Crypto is not available');
    const digest = await subtle.digest('SHA-1', new TextEncoder().encode(text));
    return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  }

  /** Split a full SHA-1 hash into the 5-character range prefix and the private suffix. */
  function splitPwnedHash(hashHex) {
    const hash = String(hashHex).toUpperCase();
    if (!/^[0-9A-F]{40}$/.test(hash)) throw new Error('Expected a 40-character SHA-1 hex digest');
    return { prefix: hash.slice(0, PWNED_PREFIX_LENGTH), suffix: hash.slice(PWNED_PREFIX_LENGTH) };
  }

  /** Build the range URL. Refuses anything other than a 5-character hex prefix. */
  function buildPwnedRangeUrl(prefix) {
    if (!/^[0-9A-F]{5}$/.test(prefix)) {
      throw new Error('Range prefix must be exactly 5 uppercase hex characters');
    }
    return PWNED_RANGE_ENDPOINT + prefix;
  }

  /** Find the breach count for a suffix in a range response body. Returns 0 when absent. */
  function parsePwnedRange(body, suffix) {
    const target = String(suffix).toUpperCase();
    for (const line of String(body).split(/\r?\n/)) {
      const separator = line.indexOf(':');
      if (separator === -1) continue;
      if (line.slice(0, separator).trim().toUpperCase() !== target) continue;
      const count = parseInt(line.slice(separator + 1).trim(), 10);
      return Number.isFinite(count) && count > 0 ? count : 0;
    }
    return 0;
  }

  /**
   * Check a password against Pwned Passwords. Only the 5-character hash prefix
   * is sent. Throws on HTTP or network failure so callers never report a
   * failed lookup as "not found".
   */
  async function checkPwnedPassword(password, options = {}) {
    const fetchImpl = options.fetchImpl || globalThis.fetch;
    if (typeof password !== 'string' || password.length === 0) throw new Error('Password is required');
    const hash = await sha1Hex(password, options.subtle || defaultSubtle());
    const { prefix, suffix } = splitPwnedHash(hash);
    const response = await fetchImpl(buildPwnedRangeUrl(prefix), {
      headers: { 'Add-Padding': 'true' },
      referrerPolicy: 'no-referrer',
    });
    if (!response.ok) throw new Error(`Range lookup failed with HTTP ${response.status}`);
    return { count: parsePwnedRange(await response.text(), suffix) };
  }

  // ============================================================
  // EMAIL BREACH CHECK (XposedOrNot)
  // ============================================================
  const XPOSED_CHECK_ENDPOINT = 'https://api.xposedornot.com/v1/check-email/';
  const XPOSED_ANALYTICS_ENDPOINT = 'https://api.xposedornot.com/v1/breach-analytics?email=';

  function isPlausibleEmail(value) {
    const email = String(value || '').trim();
    return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  /**
   * Normalize either XposedOrNot response shape into [{ name, domain }].
   * check-email returns { breaches: [["Adobe", "LinkedIn"]] } (an array of arrays).
   * breach-analytics returns { ExposedBreaches: { breaches_details: [{ breach, domain }] } }.
   */
  function normalizeXposedBreaches(data) {
    if (!data || typeof data !== 'object') return [];
    const seen = new Map();
    const add = (name, domain) => {
      const clean = typeof name === 'string' ? name.trim() : '';
      if (!clean || seen.has(clean.toLowerCase())) return;
      seen.set(clean.toLowerCase(), domain ? { name: clean, domain: String(domain) } : { name: clean });
    };
    const walk = (item) => {
      if (Array.isArray(item)) item.forEach(walk);
      else if (typeof item === 'string') add(item);
      else if (item && typeof item === 'object') add(item.name || item.breach, item.domain);
    };
    if (Array.isArray(data.breaches)) walk(data.breaches);
    const details = data.ExposedBreaches && data.ExposedBreaches.breaches_details;
    if (Array.isArray(details)) walk(details);
    return [...seen.values()];
  }

  /**
   * Look up an email address. Returns { status: 'found' | 'clean' | 'error', breaches, httpStatus }.
   * Rate limits (429) and server errors are reported as 'error', never as 'clean'.
   */
  async function checkEmailExposure(email, options = {}) {
    const fetchImpl = options.fetchImpl || globalThis.fetch;
    const address = String(email || '').trim();
    if (!isPlausibleEmail(address)) throw new Error('Enter a valid email address');
    const verdict = (breaches, httpStatus) => ({
      status: breaches.length > 0 ? 'found' : 'clean',
      breaches,
      httpStatus,
    });

    let response;
    try {
      response = await fetchImpl(XPOSED_CHECK_ENDPOINT + encodeURIComponent(address), { referrerPolicy: 'no-referrer' });
    } catch {
      response = null;
    }

    if (response) {
      if (response.status === 404) return verdict([], 404);
      if (!response.ok) return { status: 'error', breaches: [], httpStatus: response.status };
      try {
        return verdict(normalizeXposedBreaches(await response.json()), response.status);
      } catch {
        return { status: 'error', breaches: [], httpStatus: response.status };
      }
    }

    // Network or CORS failure on the primary endpoint: try the analytics endpoint once.
    try {
      const fallback = await fetchImpl(XPOSED_ANALYTICS_ENDPOINT + encodeURIComponent(address), { referrerPolicy: 'no-referrer' });
      if (fallback.status === 404) return verdict([], 404);
      if (!fallback.ok) return { status: 'error', breaches: [], httpStatus: fallback.status };
      return verdict(normalizeXposedBreaches(await fallback.json()), fallback.status);
    } catch {
      return { status: 'error', breaches: [], httpStatus: null };
    }
  }

  // ============================================================
  // DNS AND EMAIL SECURITY
  // ============================================================
  const LABEL_PATTERN = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

  /** Accept a domain, URL or email address and return a bare lowercase domain, or null. */
  function normalizeDomainInput(raw) {
    let value = String(raw || '').trim().toLowerCase();
    if (!value) return null;
    value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
    value = value.split(/[/?#]/)[0];
    if (value.includes('@')) value = value.slice(value.lastIndexOf('@') + 1);
    value = value.replace(/:\d+$/, '').replace(/\.$/, '');
    if (!value || value.length > 253) return null;
    const labels = value.split('.');
    if (labels.length < 2) return null;
    if (!labels.every((label) => LABEL_PATTERN.test(label))) return null;
    if (/^\d+$/.test(labels[labels.length - 1])) return null; // bare IPv4 addresses are not domains
    return value;
  }

  const DNS_TYPE_NAMES = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 46: 'RRSIG', 257: 'CAA' };

  function dnsTypeName(type) {
    const code = Number(type);
    return DNS_TYPE_NAMES[code] || `TYPE${Number.isFinite(code) ? code : '?'}`;
  }

  /**
   * DNS-over-HTTPS JSON returns TXT data as one or more quoted strings,
   * for example "\"v=spf1 include:a\" \" -all\"". Join them into the record value.
   */
  function joinTxtData(data) {
    const text = String(data || '').trim();
    if (!text.startsWith('"')) return text;
    const parts = [];
    const pattern = /"((?:[^"\\]|\\.)*)"/g;
    let match;
    while ((match = pattern.exec(text)) !== null) parts.push(match[1].replace(/\\(.)/g, '$1'));
    return parts.join('');
  }

  /** Extract TXT record values from a DoH JSON response. */
  function txtValues(dohResponse) {
    const answers = (dohResponse && Array.isArray(dohResponse.Answer)) ? dohResponse.Answer : [];
    return answers.filter((a) => Number(a.type) === 16 || a.type === undefined).map((a) => joinTxtData(a.data));
  }

  function evaluateSpf(values) {
    const records = (values || []).filter((v) => /^v=spf1(\s|$)/i.test(String(v).trim()));
    const name = 'SPF Record';
    if (records.length === 0) {
      return { icon: 'fail', name, detail: 'No SPF record found. Receivers cannot check who may send mail for this domain' };
    }
    if (records.length > 1) {
      return { icon: 'fail', name, detail: 'Multiple SPF records found. Receivers treat this as a permanent error (RFC 7208)', value: records.join(' | ') };
    }
    const record = records[0].trim();
    if (/(?:^|\s)\+?all(?:\s|$)/i.test(record)) {
      return { icon: 'fail', name, detail: 'SPF ends in +all, which authorizes any sender', value: record };
    }
    if (/(?:^|\s)\?all(?:\s|$)/i.test(record)) {
      return { icon: 'warn', name, detail: 'SPF ends in ?all (neutral), which gives receivers no guidance', value: record };
    }
    return { icon: 'pass', name, detail: 'Sender Policy Framework is configured', value: record };
  }

  /** Parse a DMARC record into a lowercase tag map. */
  function parseDmarcTags(record) {
    const tags = {};
    for (const part of String(record || '').split(';')) {
      const eq = part.indexOf('=');
      if (eq === -1) continue;
      const key = part.slice(0, eq).trim().toLowerCase();
      if (key && !(key in tags)) tags[key] = part.slice(eq + 1).trim();
    }
    return tags;
  }

  function evaluateDmarc(values) {
    const records = (values || []).filter((v) => /^v=DMARC1\s*(;|$)/i.test(String(v).trim()));
    const name = 'DMARC Policy';
    if (records.length === 0) {
      return { icon: 'fail', name, detail: 'No DMARC record found. The domain is easier to spoof' };
    }
    if (records.length > 1) {
      return { icon: 'fail', name, detail: 'Multiple DMARC records found. Receivers ignore DMARC in this case (RFC 7489)', value: records.join(' | ') };
    }
    const record = records[0].trim();
    const policy = (parseDmarcTags(record).p || '').toLowerCase();
    if (policy === 'reject' || policy === 'quarantine') {
      return { icon: 'pass', name, detail: `Policy: ${policy}`, value: record };
    }
    if (policy === 'none') {
      return { icon: 'warn', name, detail: 'Policy: none (monitoring only, not enforcing)', value: record };
    }
    return { icon: 'warn', name, detail: 'DMARC record has no valid p= policy tag', value: record };
  }

  /** True if any TXT value looks like a published (non-revoked) DKIM key. */
  function hasDkimKey(values) {
    return (values || []).some((v) => /(?:^|;)\s*p=[A-Za-z0-9+/]{16,}/.test(String(v)));
  }

  function evaluateDnssec(dohResponse) {
    const validated = Boolean(dohResponse && dohResponse.AD);
    return {
      icon: validated ? 'pass' : 'warn',
      name: 'DNSSEC',
      detail: validated ? 'DNSSEC signatures are validated for this domain' : 'DNSSEC is not enabled or not validated',
    };
  }

  // ============================================================
  // WEBRTC LEAK DETECTION
  // ============================================================
  function isIPv4(value) {
    const parts = String(value).split('.');
    return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
  }

  function isIPv6(value) {
    return String(value).includes(':') && /^[0-9a-f:.]+$/i.test(String(value));
  }

  /** RFC 1918, loopback, link-local and carrier-grade NAT ranges. */
  function isPrivateIPv4(value) {
    if (!isIPv4(value)) return false;
    const [a, b] = String(value).split('.').map(Number);
    return a === 10 || a === 127 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254) ||
      (a === 100 && b >= 64 && b <= 127);
  }

  /** Parse an ICE candidate line into { address, type, protocol }. */
  function parseIceCandidate(candidate) {
    const parts = String(candidate || '').replace(/^a=/, '').trim().split(/\s+/);
    if (parts.length < 8) return null;
    const typIndex = parts.indexOf('typ');
    return {
      protocol: parts[2].toLowerCase(),
      address: parts[4],
      type: typIndex !== -1 ? parts[typIndex + 1] : null,
    };
  }

  /**
   * Split candidates into addresses the page can learn about the device.
   * Host candidates with a literal IP are a local address leak; modern
   * browsers hide them behind random .local mDNS names. Server-reflexive
   * (srflx) candidates are the public address seen by the STUN server.
   */
  function classifyIceCandidates(candidates) {
    const local = new Set();
    const reflexive = new Set();
    for (const raw of candidates || []) {
      const parsed = typeof raw === 'string' ? parseIceCandidate(raw) : raw;
      if (!parsed || !parsed.address) continue;
      const address = parsed.address;
      if (address.endsWith('.local')) continue;
      if (!isIPv4(address) && !isIPv6(address)) continue;
      if (parsed.type === 'host') local.add(address);
      else if (parsed.type === 'srflx' || parsed.type === 'prflx') reflexive.add(address);
    }
    return { localAddresses: [...local], publicAddresses: [...reflexive] };
  }

  /** Turn classified candidates into a scan check. knownPublicIp is the address from the IP lookup. */
  function evaluateWebRtc(classified, knownPublicIp) {
    const name = 'WebRTC Leak';
    const local = (classified && classified.localAddresses) || [];
    const reflexive = (classified && classified.publicAddresses) || [];
    if (local.length > 0) {
      return { icon: 'warn', name, detail: `Local network addresses exposed via WebRTC: ${local.join(', ')}` };
    }
    if (knownPublicIp) {
      const sameFamily = reflexive.filter((ip) => isIPv4(ip) === isIPv4(knownPublicIp));
      const mismatched = sameFamily.filter((ip) => ip !== knownPublicIp);
      if (mismatched.length > 0) {
        return { icon: 'warn', name, detail: `WebRTC reveals a public address different from your HTTP address (${mismatched.join(', ')}). A VPN or proxy may be leaking` };
      }
    }
    return { icon: 'pass', name, detail: 'No local addresses exposed via WebRTC' };
  }

  // ============================================================
  // PASSWORD GENERATOR
  // ============================================================
  const CHARSETS = {
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lower: 'abcdefghijklmnopqrstuvwxyz',
    numbers: '0123456789',
    symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?',
    hex: '0123456789abcdef',
  };

  function defaultGetRandomValues(array) {
    return globalThis.crypto.getRandomValues(array);
  }

  /** Uniform integer in [0, max) using rejection sampling, so there is no modulo bias. */
  function secureRandomInt(max, getRandomValues = defaultGetRandomValues) {
    if (!Number.isInteger(max) || max <= 0 || max > 0x100000000) throw new RangeError('max must be an integer in 1..2^32');
    const limit = Math.floor(0x100000000 / max) * max;
    const buffer = new Uint32Array(1);
    for (;;) {
      getRandomValues(buffer);
      if (buffer[0] < limit) return buffer[0] % max;
    }
  }

  /** Random string from a character pool. Entropy is computed from the pool, not the output. */
  function generateFromPool(pool, length, getRandomValues = defaultGetRandomValues) {
    const chars = [...new Set(String(pool || ''))];
    if (chars.length === 0) throw new Error('Select at least one character set');
    if (!Number.isInteger(length) || length < 1) throw new RangeError('length must be a positive integer');
    let value = '';
    for (let i = 0; i < length; i++) value += chars[secureRandomInt(chars.length, getRandomValues)];
    return { value, entropyBits: length * Math.log2(chars.length) };
  }

  /** Random passphrase from a word list. Entropy is words * log2(unique list size). */
  function generatePassphrase(words, count = 5, separator = '-', getRandomValues = defaultGetRandomValues) {
    const list = [...new Set(words || [])];
    if (list.length < 2) throw new Error('Word list is too small');
    const picked = [];
    for (let i = 0; i < count; i++) picked.push(list[secureRandomInt(list.length, getRandomValues)]);
    return { value: picked.join(separator), entropyBits: count * Math.log2(list.length) };
  }

  function strengthFromEntropy(bits) {
    if (bits < 40) return { level: 'weak', label: 'Weak', percent: 20 };
    if (bits < 60) return { level: 'fair', label: 'Fair', percent: 40 };
    if (bits < 80) return { level: 'good', label: 'Good', percent: 60 };
    if (bits < 100) return { level: 'strong', label: 'Strong', percent: 80 };
    return { level: 'very-strong', label: 'Very Strong', percent: 100 };
  }

  // ============================================================
  // SPEED TEST MATH
  // ============================================================
  /**
   * Latency summary from samples in the order they were taken.
   * Outliers (top and bottom 10% when there are 10+ samples) are dropped.
   * Ping is the median; jitter is the mean absolute difference between
   * consecutive kept samples, in time order.
   */
  function summarizeLatency(samples) {
    const valid = (samples || []).filter((s) => Number.isFinite(s) && s >= 0);
    if (valid.length === 0) return { ping: 0, jitter: 0 };
    const sorted = [...valid].sort((a, b) => a - b);
    const trim = valid.length >= 10 ? Math.floor(valid.length * 0.1) : 0;
    const low = sorted[trim];
    const high = sorted[sorted.length - 1 - trim];
    const kept = valid.filter((s) => s >= low && s <= high);
    const keptSorted = [...kept].sort((a, b) => a - b);
    const mid = Math.floor(keptSorted.length / 2);
    const ping = keptSorted.length % 2 ? keptSorted[mid] : (keptSorted[mid - 1] + keptSorted[mid]) / 2;
    let jitter = 0;
    if (kept.length > 1) {
      let sum = 0;
      for (let i = 1; i < kept.length; i++) sum += Math.abs(kept[i] - kept[i - 1]);
      jitter = sum / (kept.length - 1);
    }
    return { ping, jitter };
  }

  /** Megabits per second for transfers that finished after the warm-up window. */
  function throughputMbps(transfers, windowStart) {
    const measured = (transfers || []).filter((t) => t.endTime > windowStart);
    if (measured.length === 0) return 0;
    const bytes = measured.reduce((sum, t) => sum + t.bytes, 0);
    const seconds = (Math.max(...measured.map((t) => t.endTime)) - windowStart) / 1000;
    return seconds > 0 ? (bytes * 8) / seconds / 1e6 : 0;
  }

  const GAUGE_RADIUS = 58;
  const GAUGE_CIRCUMFERENCE = 2 * Math.PI * GAUGE_RADIUS;

  function gaugeDashOffset(mbps, maxMbps = 300) {
    const fraction = Math.min(Math.max(Number(mbps) || 0, 0) / maxMbps, 1);
    return GAUGE_CIRCUMFERENCE * (1 - fraction);
  }

  // ============================================================
  // IP GEOLOCATION PARSERS
  // ============================================================
  function parseIpapiCo(d) {
    if (!d || d.error) return null;
    return {
      ip: d.ip, isp: d.org || 'N/A', org: d.org || 'N/A',
      asn: d.asn || 'N/A', type: d.version || 'N/A',
      proxy: false, hosting: false,
      country: d.country_name, countryCode: d.country_code,
      region: d.region, city: d.city, postal: d.postal,
      lat: d.latitude, lng: d.longitude,
      timezone: d.timezone,
    };
  }

  function parseIpwhois(d) {
    if (!d || !d.success) return null;
    const connection = d.connection || {};
    const security = d.security || {};
    return {
      ip: d.ip, isp: connection.isp || 'N/A', org: connection.org || 'N/A',
      asn: connection.asn ? `AS${connection.asn}` : 'N/A', type: d.type || 'N/A',
      proxy: Boolean(security.proxy), hosting: Boolean(security.hosting),
      country: d.country, countryCode: d.country_code,
      region: d.region, city: d.city, postal: d.postal,
      lat: d.latitude, lng: d.longitude,
      timezone: (d.timezone && d.timezone.id) || 'N/A',
    };
  }

  function parseFreeipapi(d) {
    if (!d || !d.ipAddress) return null;
    return {
      ip: d.ipAddress, isp: d.isp || 'N/A', org: d.isp || 'N/A',
      asn: 'N/A', type: d.ipVersion ? `IPv${d.ipVersion}` : 'N/A',
      proxy: Boolean(d.isProxy), hosting: false,
      country: d.countryName, countryCode: d.countryCode,
      region: d.regionName, city: d.cityName, postal: d.zipCode,
      lat: d.latitude, lng: d.longitude,
      timezone: d.timeZone,
    };
  }

  function countryFlag(code) {
    if (typeof code !== 'string' || !/^[A-Za-z]{2}$/.test(code)) return '';
    return String.fromCodePoint(...[...code.toUpperCase()].map((c) => 0x1F1E6 + c.charCodeAt(0) - 65));
  }

  // ============================================================
  // TEXT REPORT
  // ============================================================
  const STATUS_TAGS = { pass: '[PASS]', fail: '[FAIL]', warn: '[WARN]', info: '[INFO]' };

  function fixed(value, digits) {
    return Number.isFinite(value) ? value.toFixed(digits) : 'n/a';
  }

  /** Plain-text export of the current results. Passwords are never part of state or the report. */
  function buildTextReport(state, generatedAt = new Date()) {
    const lines = ['=== NetScope Results ===', `Generated: ${generatedAt.toLocaleString()}`, ''];
    if (state && state.ip) {
      lines.push('--- IP & Location ---', `IP: ${state.ip}`);
      if (state.geo) {
        const g = state.geo;
        lines.push(`ISP: ${g.isp}`, `Org: ${g.org}`, `ASN: ${g.asn}`, `Type: ${g.type}`);
        lines.push(`Country: ${g.country}`, `Region: ${g.region}`, `City: ${g.city}`);
        lines.push(`Coords: ${g.lat}, ${g.lng}`, `Timezone: ${g.timezone}`);
      }
      lines.push('');
    }
    if (state && state.speed && state.speed.ping !== null && state.speed.ping !== undefined) {
      const s = state.speed;
      lines.push('--- Speed Test ---',
        `Ping: ${fixed(s.ping, 0)} ms`,
        `Jitter: ${fixed(s.jitter, 1)} ms`,
        `Download: ${fixed(s.download, 1)} Mbps`,
        `Upload: ${fixed(s.upload, 1)} Mbps`,
        '');
    }
    if (state && state.scan) {
      lines.push(`--- DNS & Security: ${state.scan.domain} ---`);
      for (const c of state.scan.checks) lines.push(`${STATUS_TAGS[c.icon] || '[?]'} ${c.name}: ${c.detail}`);
      lines.push('');
    }
    lines.push('Generated by NetScope');
    return lines.join('\n');
  }

  return {
    escapeHtml,
    sha1Hex, splitPwnedHash, buildPwnedRangeUrl, parsePwnedRange, checkPwnedPassword,
    isPlausibleEmail, normalizeXposedBreaches, checkEmailExposure,
    normalizeDomainInput, dnsTypeName, joinTxtData, txtValues,
    evaluateSpf, parseDmarcTags, evaluateDmarc, hasDkimKey, evaluateDnssec,
    isIPv4, isIPv6, isPrivateIPv4, parseIceCandidate, classifyIceCandidates, evaluateWebRtc,
    CHARSETS, secureRandomInt, generateFromPool, generatePassphrase, strengthFromEntropy,
    summarizeLatency, throughputMbps, gaugeDashOffset, GAUGE_CIRCUMFERENCE,
    parseIpapiCo, parseIpwhois, parseFreeipapi, countryFlag,
    buildTextReport,
  };
});
