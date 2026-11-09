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
    const tags = parseDmarcTags(record);
    const policy = (tags.p || '').toLowerCase();
    if (policy === 'reject' || policy === 'quarantine') {
      const pct = tags.pct === undefined ? 100 : Number(tags.pct);
      if (Number.isFinite(pct) && pct >= 0 && pct < 100) {
        return { icon: 'warn', name, detail: `Policy: ${policy}, but only applied to ${pct}% of failing mail`, value: record };
      }
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

  /**
   * MTA-STS (RFC 8461) tells sending servers to require TLS when delivering to
   * this domain. The TXT record at _mta-sts.<domain> announces the policy.
   */
  function evaluateMtaSts(values) {
    const records = (values || []).filter((v) => /^v=STSv1\s*(;|$)/i.test(String(v).trim()));
    const name = 'MTA-STS';
    if (records.length === 0) {
      return { icon: 'info', name, detail: 'No MTA-STS policy. Optional: it makes other mail servers require TLS when sending to this domain' };
    }
    if (records.length > 1) {
      return { icon: 'warn', name, detail: 'Multiple MTA-STS records found. Senders ignore the policy in this case (RFC 8461)', value: records.join(' | ') };
    }
    const id = parseDmarcTags(records[0]).id || '';
    if (!/^[A-Za-z0-9]{1,32}$/.test(id)) {
      return { icon: 'warn', name, detail: 'MTA-STS record is missing a valid id= tag', value: records[0].trim() };
    }
    return { icon: 'pass', name, detail: 'MTA-STS is announced. Senders should fetch the policy over HTTPS', value: records[0].trim() };
  }

  /** SMTP TLS reporting (RFC 8460) at _smtp._tls.<domain>. */
  function evaluateTlsRpt(values) {
    const records = (values || []).filter((v) => /^v=TLSRPTv1\s*(;|$)/i.test(String(v).trim()));
    const name = 'TLS Reporting';
    if (records.length === 0) {
      return { icon: 'info', name, detail: 'No TLS-RPT record. Optional: it asks senders to report TLS delivery failures' };
    }
    const rua = parseDmarcTags(records[0]).rua || '';
    if (!/^(mailto:|https:)/i.test(rua)) {
      return { icon: 'warn', name, detail: 'TLS-RPT record has no valid rua= reporting address', value: records[0].trim() };
    }
    return { icon: 'pass', name, detail: 'TLS failure reports are requested', value: records[0].trim() };
  }

  /** BIMI (brand logo in supporting inboxes) at default._bimi.<domain>. Needs enforced DMARC to take effect. */
  function evaluateBimi(values, dmarcCheck) {
    const records = (values || []).filter((v) => /^v=BIMI1\s*(;|$)/i.test(String(v).trim()));
    const name = 'BIMI';
    if (records.length === 0) {
      return { icon: 'info', name, detail: 'No BIMI record. Optional: it lets supporting inboxes show your logo' };
    }
    const tags = parseDmarcTags(records[0]);
    const logo = tags.l || '';
    if (logo && !/^https:\/\//i.test(logo)) {
      return { icon: 'warn', name, detail: 'BIMI logo (l=) must be an HTTPS URL', value: records[0].trim() };
    }
    if (dmarcCheck && dmarcCheck.icon !== 'pass') {
      return { icon: 'warn', name, detail: 'BIMI is published but inboxes ignore it until DMARC is enforced (quarantine or reject at 100%)', value: records[0].trim() };
    }
    const vmc = tags.a ? ' with a certificate (a=)' : ' without a certificate, which some inboxes require';
    return { icon: 'pass', name, detail: `BIMI is published${vmc}`, value: records[0].trim() };
  }

  /** Common DKIM selectors. Selectors are not discoverable, so a miss is not a failure. */
  const DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 'k1', 'k2', 's1', 's2', 'dkim', 'mail', 'smtp', 'fm1', 'fm2', 'fm3', 'mx', 'protonmail', 'zoho', 'mandrill'];

  function evaluateDkim(foundSelectors, probedCount = DKIM_SELECTORS.length) {
    const found = (foundSelectors || []).filter(Boolean);
    if (found.length > 0) {
      return { icon: 'pass', name: 'DKIM', detail: `DKIM key${found.length > 1 ? 's' : ''} found at selector${found.length > 1 ? 's' : ''}: ${found.join(', ')}` };
    }
    return { icon: 'info', name: 'DKIM', detail: `No DKIM key at ${probedCount} common selectors. The domain may still sign mail with a custom selector` };
  }

  /** DNS response codes worth naming to a person. */
  const DNS_RCODES = { 0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 5: 'REFUSED' };

  /** Plain-language meaning of each status, shown under each check. */
  const CHECK_EXPLANATIONS = {
    'SPF Record': 'SPF lists the servers allowed to send mail as this domain.',
    'DMARC Policy': 'DMARC tells receivers what to do with mail that fails SPF and DKIM: nothing, spam folder, or reject.',
    DKIM: 'DKIM adds a signature to outgoing mail so receivers can tell it was not altered or forged.',
    DNSSEC: 'DNSSEC signs DNS answers so they cannot be quietly swapped in transit.',
    'MTA-STS': 'MTA-STS stops attackers from downgrading incoming mail to unencrypted delivery.',
    'TLS Reporting': 'TLS-RPT sends you reports when other servers fail to deliver mail to you securely.',
    BIMI: 'BIMI shows a verified brand logo next to your mail in some inboxes.',
    'Mail Servers': 'MX records say which servers accept mail for this domain.',
  };

  /** Count results by severity and give one overall verdict. */
  function summarizeChecks(checks) {
    const counts = { pass: 0, warn: 0, fail: 0, info: 0 };
    for (const c of checks || []) if (c && c.icon in counts) counts[c.icon]++;
    let verdict = 'good';
    if (counts.fail > 0) verdict = 'at-risk';
    else if (counts.warn > 0) verdict = 'needs-attention';
    const labels = { good: 'Looks good', 'needs-attention': 'Needs attention', 'at-risk': 'At risk' };
    return { ...counts, verdict, label: labels[verdict] };
  }

  /**
   * Run the domain checks. doh(name, type, extra) must resolve to DoH JSON or throw.
   * Returns { status: 'ok' | 'nxdomain' | 'error', records, checks, failedLookups }.
   * Every check that could not be looked up says so instead of being graded as missing.
   */
  async function scanDomain(domain, doh) {
    const settle = (promise) => promise.then((value) => ({ ok: true, value }), (error) => ({ ok: false, error }));
    const q = (name, type, extra) => settle(Promise.resolve().then(() => doh(name, type, extra)));

    const [a, aaaa, mx, ns, txt, dmarc, mtaSts, tlsRpt, bimi, dnssec, ...dkim] = await Promise.all([
      q(domain, 'A'), q(domain, 'AAAA'), q(domain, 'MX'), q(domain, 'NS'),
      q(domain, 'TXT'), q(`_dmarc.${domain}`, 'TXT'), q(`_mta-sts.${domain}`, 'TXT'),
      q(`_smtp._tls.${domain}`, 'TXT'), q(`default._bimi.${domain}`, 'TXT'), q(domain, 'A', '&do=1'),
      ...DKIM_SELECTORS.map((sel) => q(`${sel}._domainkey.${domain}`, 'TXT')),
    ]);

    const recordLookups = [a, aaaa, mx, ns];
    const okLookups = recordLookups.filter((r) => r.ok);
    if (okLookups.length === 0) {
      return { status: 'error', records: [], checks: [], failedLookups: recordLookups.length };
    }
    const nx = okLookups.some((r) => Number(r.value && r.value.Status) === 3);
    if (nx) return { status: 'nxdomain', records: [], checks: [], failedLookups: 0 };

    const records = [];
    for (const r of okLookups) {
      for (const rec of (r.value && r.value.Answer) || []) {
        if ([1, 2, 15, 28].includes(Number(rec.type))) records.push({ type: dnsTypeName(rec.type), data: String(rec.data), ttl: rec.TTL });
      }
    }

    const graded = (lookup, evaluate, name, label) => {
      if (!lookup.ok) return { icon: 'warn', name, detail: `Could not look up ${label}. Try again` };
      const status = Number(lookup.value && lookup.value.Status);
      if (status && status !== 3) return { icon: 'warn', name, detail: `${label} lookup returned ${DNS_RCODES[status] || 'error ' + status}` };
      return evaluate(txtValues(lookup.value));
    };

    const checks = [];
    checks.push(graded(txt, evaluateSpf, 'SPF Record', 'SPF'));
    const dmarcCheck = graded(dmarc, evaluateDmarc, 'DMARC Policy', 'DMARC');
    checks.push(dmarcCheck);
    const found = DKIM_SELECTORS.filter((sel, i) => dkim[i].ok && hasDkimKey(txtValues(dkim[i].value)));
    checks.push(evaluateDkim(found));
    checks.push(dnssec.ok ? evaluateDnssec(dnssec.value) : { icon: 'warn', name: 'DNSSEC', detail: 'Could not verify DNSSEC' });
    if (mx.ok) {
      const answers = ((mx.value && mx.value.Answer) || []).filter((r) => Number(r.type) === 15);
      const nullMx = answers.length === 1 && /^\s*0\s+\.?\s*$/.test(String(answers[0].data));
      if (nullMx) checks.push({ icon: 'info', name: 'Mail Servers', detail: 'Null MX (RFC 7505): this domain states it does not accept email' });
      else checks.push(answers.length > 0
        ? { icon: 'info', name: 'Mail Servers', detail: `${answers.length} MX record(s) found`, value: answers.map((r) => r.data).join(', ') }
        : { icon: 'warn', name: 'Mail Servers', detail: 'No MX records found. The domain may not receive email' });
    }
    checks.push(graded(mtaSts, evaluateMtaSts, 'MTA-STS', 'MTA-STS'));
    checks.push(graded(tlsRpt, evaluateTlsRpt, 'TLS Reporting', 'TLS-RPT'));
    checks.push(graded(bimi, (v) => evaluateBimi(v, dmarcCheck), 'BIMI', 'BIMI'));

    for (const c of checks) if (!c.explain && CHECK_EXPLANATIONS[c.name]) c.explain = CHECK_EXPLANATIONS[c.name];
    return { status: 'ok', records, checks, failedLookups: recordLookups.length - okLookups.length };
  }

  // ============================================================
  // NETWORK HELPERS
  // ============================================================
  /**
   * fetch with a deadline. Aborts the request (including the body read) after
   * timeoutMs so one slow provider cannot stall a fallback chain forever.
   */
  async function fetchWithTimeout(url, init = {}, options = {}) {
    const fetchImpl = options.fetchImpl || globalThis.fetch;
    const timeoutMs = options.timeoutMs || 8000;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      return await fetchImpl(url, { ...init, signal: controller.signal });
    } catch (err) {
      if (controller.signal.aborted) {
        const timeout = new Error(`Request timed out after ${timeoutMs} ms`);
        timeout.name = 'TimeoutError';
        throw timeout;
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }

  /** True for a syntactically valid IPv4 or IPv6 address string from an IP echo service. */
  function isIpAddress(value) {
    const text = String(value || '').trim();
    if (isIPv4(text)) return true;
    if (!isIPv6(text) || text.length > 45) return false;
    const groups = text.split('::');
    if (groups.length > 2) return false;
    const parts = text.split(':');
    if (parts.length > 8 || (groups.length === 1 && parts.length !== 8 && !isIPv4(parts[parts.length - 1]))) return false;
    return text.split(':').every((g) => g === '' || /^[0-9a-f]{1,4}$/i.test(g) || isIPv4(g));
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

  const STRENGTH_SCORES = { weak: 1, fair: 2, good: 3, strong: 4, 'very-strong': 5 };
  const STRENGTH_LABELS = { 1: 'Weak', 2: 'Fair', 3: 'Good', 4: 'Strong', 5: 'Very Strong' };

  /**
   * Rough strength estimate for a password someone typed, from its character
   * classes and length. Repeated characters count half. A password found in a
   * breach corpus is weak no matter how it looks. Returns the level, label and
   * a score from 1 to 5; it never returns or keeps the password itself.
   */
  function estimatePasswordStrength(password, options = {}) {
    const text = String(password || '');
    const chars = [...text];
    let pool = 0;
    if (/[a-z]/.test(text)) pool += 26;
    if (/[A-Z]/.test(text)) pool += 26;
    if (/[0-9]/.test(text)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(text)) pool += 33;
    const unique = new Set(chars).size;
    const effectiveLength = unique + (chars.length - unique) * 0.5;
    const bits = pool > 0 ? effectiveLength * Math.log2(pool) : 0;
    const strength = options.breached ? strengthFromEntropy(0) : strengthFromEntropy(bits);
    return { level: strength.level, label: strength.label, score: STRENGTH_SCORES[strength.level], outOf: 5 };
  }

  /**
   * The only password check data the app keeps: whether it was found in a
   * breach and its strength score. No password, hash, prefix or breach count.
   */
  function passwordCheckSummary(password, breachCount) {
    const found = Number(breachCount) > 0;
    const { label, score, outOf } = estimatePasswordStrength(password, { breached: found });
    return { found, strength: { label, score, outOf } };
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
  // SPEED TEST TIMING (deadlines, cancel, partial results)
  // ============================================================
  // Every speed test request runs under a deadline linked to the run's cancel
  // signal, so a stalled connection ends the phase instead of hanging the tool.
  // Clocks and timers are injectable so tests can drive time with fakes.
  const defaultTimers = {
    setTimeout: (fn, ms) => setTimeout(fn, ms),
    clearTimeout: (id) => clearTimeout(id),
  };
  const defaultNow = () => (globalThis.performance ? globalThis.performance.now() : Date.now());

  /** Abort reason that says why: 'cancelled' (user) or 'timeout' (deadline). */
  function speedAbortReason(kind) {
    const err = new Error(kind === 'timeout' ? 'Speed test request timed out' : 'Speed test cancelled');
    err.name = kind === 'timeout' ? 'TimeoutError' : 'AbortError';
    err.kind = kind === 'timeout' ? 'timeout' : 'cancelled';
    return err;
  }

  /** 'cancelled', 'timeout' or null for a signal. An abort without a reason counts as cancelled. */
  function abortKind(signal) {
    if (!signal || !signal.aborted) return null;
    const reason = signal.reason;
    return reason && reason.kind === 'timeout' ? 'timeout' : 'cancelled';
  }

  /**
   * An AbortSignal that fires after timeoutMs or when the parent signal aborts,
   * whichever comes first. Call clear() when the work finishes.
   */
  function createDeadline(timeoutMs, options = {}) {
    const timers = options.timers || defaultTimers;
    const parent = options.signal;
    const controller = new AbortController();
    let timer = null;
    const onParent = () => abort(parent.reason || speedAbortReason('cancelled'));
    function clear() {
      if (timer !== null) { timers.clearTimeout(timer); timer = null; }
      if (parent) parent.removeEventListener('abort', onParent);
    }
    function abort(reason) {
      if (!controller.signal.aborted) controller.abort(reason);
      clear();
    }
    if (parent && parent.aborted) {
      abort(parent.reason || speedAbortReason('cancelled'));
    } else {
      if (parent) parent.addEventListener('abort', onParent);
      if (Number.isFinite(timeoutMs)) timer = timers.setTimeout(() => abort(speedAbortReason('timeout')), timeoutMs);
    }
    return { signal: controller.signal, clear };
  }

  /** Rejects with the signal's reason as soon as it aborts, even if the work ignores the signal. */
  function raceAbort(promise, signal) {
    if (!signal) return promise;
    if (signal.aborted) return Promise.reject(signal.reason || speedAbortReason('cancelled'));
    let onAbort;
    const aborted = new Promise((_, reject) => {
      onAbort = () => reject(signal.reason || speedAbortReason('cancelled'));
      signal.addEventListener('abort', onAbort);
    });
    return Promise.race([promise, aborted]).finally(() => signal.removeEventListener('abort', onAbort));
  }

  /**
   * Phase outcome: cancelled (user), failed (nothing measured), partial (some
   * results, but a request stalled past its deadline or errored) or complete.
   */
  function phaseStatus(parent, deadline, measured, failed) {
    if (abortKind(parent) === 'cancelled') return 'cancelled';
    if (measured === 0) return 'failed';
    if (abortKind(deadline) === 'timeout' || failed) return 'partial';
    return 'complete';
  }

  /**
   * Latency samples. ping(i, signal) does one round trip. Each ping has its own
   * deadline (a lost ping is skipped) and the whole phase has a hard deadline.
   * Returns { samples, lost, status } (see phaseStatus).
   */
  async function measureLatency(options) {
    const { ping, count = 20, pingTimeoutMs = 2000, totalMs = 8000, signal } = options;
    const timers = options.timers || defaultTimers;
    const now = options.now || defaultNow;
    const phase = createDeadline(totalMs, { signal, timers });
    const samples = [];
    let lost = 0;
    try {
      for (let i = 0; i < count && !phase.signal.aborted; i++) {
        const one = createDeadline(pingTimeoutMs, { signal: phase.signal, timers });
        const start = now();
        try {
          await raceAbort(Promise.resolve().then(() => ping(i, one.signal)), one.signal);
          samples.push(now() - start);
        } catch {
          if (phase.signal.aborted) break;
          lost++;
        } finally {
          one.clear();
        }
      }
    } finally {
      phase.clear();
    }
    const status = phaseStatus(signal, phase.signal, samples.length, lost > 0 && samples.length < count / 2);
    return { samples, lost, status };
  }

  /**
   * Time-based multi-connection transfer phase (download or upload).
   * transfer(size, id, signal) moves `size` bytes and resolves with the byte
   * count. Workers keep going until durationMs; anything still in flight at
   * durationMs + graceMs is aborted. Completed transfers always count, so a
   * cancelled or stalled phase still reports a partial speed.
   * Returns { mbps (null when nothing finished), transfers, status }.
   */
  async function runTransferPhase(options) {
    const {
      transfer, signal, onProgress, onSample,
      connections = 4, durationMs = 12000, warmupMs = 2000, graceMs = 3000,
      initialSize = 100000, maxSize = 25000000,
    } = options;
    const timers = options.timers || defaultTimers;
    const now = options.now || defaultNow;
    const phase = createDeadline(durationMs + graceMs, { signal, timers });
    const transfers = [];
    const start = now();
    let failed = false;

    async function worker(id) {
      let size = initialSize;
      while (now() - start < durationMs && !phase.signal.aborted) {
        const fetchStart = now();
        try {
          const bytes = await raceAbort(Promise.resolve().then(() => transfer(size, id, phase.signal)), phase.signal);
          const fetchEnd = now();
          transfers.push({ bytes: Number(bytes) || 0, endTime: fetchEnd });
          const took = fetchEnd - fetchStart;
          if (took < 500) size = Math.min(size * 6, maxSize);
          else if (took < 1500) size = Math.min(size * 3, maxSize);
          else if (took < 3000) size = Math.min(Math.round(size * 1.5), maxSize);
          if (onProgress) onProgress(Math.min((fetchEnd - start) / durationMs, 1) * 100);
          if (onSample && fetchEnd - start > warmupMs) onSample(throughputMbps(transfers, start + warmupMs));
        } catch {
          if (!phase.signal.aborted) failed = true;
          break;
        }
      }
    }

    try {
      const workers = [];
      for (let i = 0; i < connections; i++) workers.push(worker(i));
      await Promise.allSettled(workers);
    } finally {
      phase.clear();
    }
    let mbps = null;
    if (transfers.length) mbps = throughputMbps(transfers, start + warmupMs) || throughputMbps(transfers, start);
    return { mbps, transfers, status: phaseStatus(signal, phase.signal, transfers.length, failed) };
  }

  /**
   * Overall verdict for the UI and report. phases maps a phase name to
   * { status, measured } in run order; measured is true when that phase has a
   * number to show. Returns { status: complete | partial | cancelled | failed, message }.
   */
  function summarizeSpeedRun(phases) {
    const entries = Object.entries(phases || {}).filter(([, p]) => p && p.status);
    const anyMeasured = entries.some(([, p]) => p.measured);
    if (entries.some(([, p]) => p.status === 'cancelled')) {
      return anyMeasured
        ? { status: 'cancelled', message: 'Test cancelled. Results measured so far are shown.' }
        : { status: 'cancelled', message: 'Test cancelled before anything was measured.' };
    }
    if (!anyMeasured) {
      return { status: 'failed', message: 'Could not reach the speed test server. Check your connection and try again.' };
    }
    const problems = entries.filter(([, p]) => p.status !== 'complete').map(([name]) => name);
    if (!problems.length) return { status: 'complete', message: 'Test complete' };
    const which = problems.length === 1 ? `${problems[0]} test` : `${problems.slice(0, -1).join(', ')} and ${problems[problems.length - 1]} tests`;
    return { status: 'partial', message: `The ${which} did not finish because the connection stalled or dropped. Partial results are shown.` };
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

  /** Plain-text export of the current results. Passwords and hashes are never part of state or the report. */
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
    const e = state && state.breach && state.breach.email;
    if (e) {
      lines.push('--- Breach Check ---');
      if (e.status === 'found') lines.push(`Email ${e.email}: found in ${e.count} breach${e.count === 1 ? '' : 'es'}`);
      else if (e.status === 'clean') lines.push(`Email ${e.email}: not found in known breaches`);
      else lines.push(`Email ${e.email}: check did not complete`);
      lines.push('');
    }
    // Password check: only found or not found and the strength score. Never the
    // password, its hash or the breach count (a count can identify a common password).
    const p = state && state.breach && state.breach.password;
    if (p && typeof p.found === 'boolean') {
      lines.push('--- Password Check ---');
      lines.push(p.found ? 'Breached: yes, found in known breaches' : 'Breached: no, not found in known breaches');
      // The label comes from the score, so nothing but a number from state reaches the report.
      const score = p.strength && p.strength.score;
      if (Number.isInteger(score) && score >= 1 && score <= 5) lines.push(`Strength: ${STRENGTH_LABELS[score]} (${score} of 5)`);
      lines.push('');
    }
    if (state && state.scan) {
      lines.push(`--- DNS & Security: ${state.scan.domain} ---`);
      const sum = summarizeChecks(state.scan.checks);
      lines.push(`Overall: ${sum.label} (${sum.pass} pass, ${sum.warn} warn, ${sum.fail} fail, ${sum.info} info)`);
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
    evaluateMtaSts, evaluateTlsRpt, evaluateBimi, evaluateDkim, DKIM_SELECTORS,
    summarizeChecks, scanDomain, fetchWithTimeout, isIpAddress,
    isIPv4, isIPv6, isPrivateIPv4, parseIceCandidate, classifyIceCandidates, evaluateWebRtc,
    CHARSETS, secureRandomInt, generateFromPool, generatePassphrase, strengthFromEntropy,
    estimatePasswordStrength, passwordCheckSummary,
    summarizeLatency, throughputMbps, gaugeDashOffset, GAUGE_CIRCUMFERENCE,
    speedAbortReason, abortKind, createDeadline, raceAbort, measureLatency, runTransferPhase, summarizeSpeedRun,
    parseIpapiCo, parseIpwhois, parseFreeipapi, countryFlag,
    buildTextReport,
  };
});
