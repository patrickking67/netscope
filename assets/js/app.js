/* ===== NetScope - Network Security Toolkit ===== */

// Pure logic lives in core.js so it can be unit tested in Node.
const Core = window.NetScopeCore;

const state = {
  ip: null, geo: null,
  speed: { ping: null, jitter: null, download: null, upload: null },
  breach: { email: null, password: null },
  scan: null,
};

// ============================================================
// INIT
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initMobileMenu();
  initTabBar();
  initExport();
  initBreachTabs();
  initPasswordToggle();
  initEventListeners();
  initPasswordGenerator();
  initFullScan();
  initSettings();

  // Firebase (guarded - works without it)
  if (typeof firebase !== 'undefined' && typeof firebaseConfig !== 'undefined' && firebaseConfig.apiKey !== 'YOUR_API_KEY') {
    if (typeof initAuth === 'function') initAuth();
    if (typeof initFirestore === 'function') initFirestore();
  } else {
    // No Firebase: check guest flag or show auth gate
    if (localStorage.getItem('netscope-guest') === 'true') {
      showDashboard();
    } else {
      showAuthGate();
    }
  }

  dismissLoadingScreen();
});

// ============================================================
// TAB BAR
// ============================================================
let ipFetched = false;

function initTabBar() {
  const tabs = [...document.querySelectorAll('.tab-bar-item')];
  tabs.forEach((tab, i) => {
    tab.addEventListener('click', () => switchTab(tab.dataset.tab));
    // Arrow keys move between tools, as in the WAI-ARIA tabs pattern.
    tab.addEventListener('keydown', e => {
      let next = null;
      if (e.key === 'ArrowRight') next = tabs[(i + 1) % tabs.length];
      else if (e.key === 'ArrowLeft') next = tabs[(i - 1 + tabs.length) % tabs.length];
      else if (e.key === 'Home') next = tabs[0];
      else if (e.key === 'End') next = tabs[tabs.length - 1];
      if (!next) return;
      e.preventDefault();
      next.focus();
      switchTab(next.dataset.tab);
    });
  });

  // Mobile drawer tool links
  document.querySelectorAll('#mobile-tool-links .mobile-nav-link[data-tab]').forEach(link => {
    link.addEventListener('click', () => {
      switchTab(link.dataset.tab);
      closeMobileMenu();
    });
  });

  // Reposition indicator on resize
  window.addEventListener('resize', () => {
    if (document.getElementById('dashboard')?.style.display !== 'none') {
      updateTabIndicator();
    }
  });
}

function switchTab(tabId) {
  // Update tab buttons
  document.querySelectorAll('.tab-bar-item').forEach(t => {
    const active = t.dataset.tab === tabId;
    t.classList.toggle('active', active);
    t.setAttribute('aria-selected', String(active));
  });

  // Update panels
  document.querySelectorAll('.tab-panel').forEach(p => {
    p.classList.toggle('active', p.dataset.panel === tabId);
  });

  updateTabIndicator();

  // Lazy-fetch IP on first visit to IP tab
  if (tabId === 'ip-location' && !ipFetched) {
    ipFetched = true;
    fetchIPInfo();
  }

  // Fix Leaflet map rendering in hidden tab
  if (tabId === 'ip-location' && window._netscopeMap) {
    setTimeout(() => window._netscopeMap.invalidateSize(), 100);
  }
}

function updateTabIndicator() {
  const indicator = document.getElementById('tab-bar-indicator');
  const activeTab = document.querySelector('.tab-bar-item.active');
  if (!indicator || !activeTab) return;

  const bar = activeTab.parentElement;
  const barRect = bar.getBoundingClientRect();
  const tabRect = activeTab.getBoundingClientRect();

  indicator.style.left = (tabRect.left - barRect.left + bar.scrollLeft) + 'px';
  indicator.style.width = tabRect.width + 'px';
}

// ============================================================
// VIEW SWITCHING (auth gate <-> dashboard)
// ============================================================
function showDashboard() {
  const authGate = document.getElementById('auth-gate');
  const dashboard = document.getElementById('dashboard');
  const fullScanBtn = document.getElementById('btn-full-scan');
  const exportTrigger = document.getElementById('export-trigger');
  const mobileToolLinks = document.getElementById('mobile-tool-links');

  if (authGate) authGate.style.display = 'none';
  if (dashboard) dashboard.style.display = '';
  if (fullScanBtn) fullScanBtn.style.display = '';
  if (exportTrigger) exportTrigger.style.display = '';
  if (mobileToolLinks) mobileToolLinks.style.display = '';

  // Position tab indicator after layout
  requestAnimationFrame(() => updateTabIndicator());

  // Auto-fetch IP on first dashboard load
  if (!ipFetched) {
    ipFetched = true;
    fetchIPInfo();
  }
}

function showAuthGate() {
  const authGate = document.getElementById('auth-gate');
  const dashboard = document.getElementById('dashboard');
  const fullScanBtn = document.getElementById('btn-full-scan');
  const exportTrigger = document.getElementById('export-trigger');
  const mobileToolLinks = document.getElementById('mobile-tool-links');

  if (authGate) authGate.style.display = '';
  if (dashboard) dashboard.style.display = 'none';
  if (fullScanBtn) fullScanBtn.style.display = 'none';
  if (exportTrigger) exportTrigger.style.display = 'none';
  if (mobileToolLinks) mobileToolLinks.style.display = 'none';
}

function initExport() {
  const trigger = document.getElementById('export-trigger');
  const panel = document.getElementById('export-panel');
  trigger.addEventListener('click', e => { e.stopPropagation(); panel.classList.toggle('open'); });
  document.addEventListener('click', e => {
    if (!panel.contains(e.target) && e.target !== trigger) panel.classList.remove('open');
  });
  document.getElementById('btn-copy').addEventListener('click', exportCopy);
  document.getElementById('btn-email').addEventListener('click', exportEmail);
  document.getElementById('btn-pdf').addEventListener('click', exportPDF);
}

function initBreachTabs() {
  document.querySelectorAll('.breach-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.breach-tab').forEach(t => { t.classList.remove('active'); t.setAttribute('aria-selected', 'false'); });
      tab.classList.add('active');
      tab.setAttribute('aria-selected', 'true');
      document.querySelectorAll('.breach-content').forEach(c => c.classList.add('hidden'));
      document.querySelector(`[data-tab-content="${tab.dataset.tab}"]`).classList.remove('hidden');
    });
  });
}

function initPasswordToggle() {
  const toggle = document.getElementById('toggle-password');
  const input = document.getElementById('password-input');
  toggle.addEventListener('click', () => {
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    toggle.setAttribute('aria-pressed', String(show));
    toggle.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
  });
}

function initEventListeners() {
  document.getElementById('btn-speed-test').addEventListener('click', runSpeedTest);
  document.getElementById('btn-speed-cancel').addEventListener('click', cancelSpeedTest);
  document.getElementById('btn-email-check').addEventListener('click', checkEmailBreach);
  document.getElementById('btn-password-check').addEventListener('click', checkPasswordBreach);
  document.getElementById('btn-scan').addEventListener('click', runDNSScan);
  document.getElementById('password-input').addEventListener('keydown', e => { if (e.key === 'Enter') checkPasswordBreach(); });
  document.getElementById('email-input').addEventListener('keydown', e => { if (e.key === 'Enter') checkEmailBreach(); });
  document.getElementById('scan-input').addEventListener('keydown', e => { if (e.key === 'Enter') runDNSScan(); });
}

// ============================================================
// IP & LOCATION - provider fallback chain
// ============================================================
async function fetchIPInfo() {
  // Step 1: Get IP
  let ip = null;
  const ipApis = [
    'https://api.ipify.org?format=json',
    'https://api.seeip.org/jsonip',
    'https://api64.ipify.org?format=json',
  ];
  for (const url of ipApis) {
    try {
      const r = await timedFetch(url);
      if (!r.ok) continue;
      const d = await r.json();
      // Only accept a real address; anything else falls through to the next provider.
      if (d && Core.isIpAddress(d.ip)) { ip = String(d.ip).trim(); break; }
    } catch {}
  }
  if (!ip) {
    document.getElementById('ip-address').textContent = 'Could not detect';
    clearSkeletons();
    return;
  }
  document.getElementById('ip-address').textContent = ip;
  state.ip = ip;

  // Step 2: Get geo/network info with fallback
  const geoApis = [
    { url: `https://ipapi.co/${encodeURIComponent(ip)}/json/`, parse: Core.parseIpapiCo },
    { url: `https://ipwho.is/${encodeURIComponent(ip)}`, parse: Core.parseIpwhois },
    { url: `https://freeipapi.com/api/json/${encodeURIComponent(ip)}`, parse: Core.parseFreeipapi },
  ];
  for (const api of geoApis) {
    try {
      const r = await timedFetch(api.url);
      if (!r.ok) continue;
      const d = await r.json();
      const geo = api.parse(d);
      if (geo && geo.country) {
        state.geo = geo;
        renderGeo(geo);
        return;
      }
    } catch {}
  }
  clearSkeletons();
}

function renderGeo(g) {
  setVal('info-isp', g.isp);
  setVal('info-org', g.org);
  setVal('info-asn', g.asn);
  setVal('info-type', g.type);
  setVal('info-proxy', g.proxy ? 'Yes - Detected' : 'No');
  setVal('info-hosting', g.hosting ? 'Yes' : 'No');
  const flag = g.countryCode ? Core.countryFlag(g.countryCode) + ' ' : '';
  setVal('geo-country', flag + (g.country || 'N/A'));
  setVal('geo-region', g.region || 'N/A');
  setVal('geo-city', g.city || 'N/A');
  setVal('geo-postal', g.postal || 'N/A');
  setVal('geo-coords', g.lat && g.lng ? `${Number(g.lat).toFixed(4)}, ${Number(g.lng).toFixed(4)}` : 'N/A');
  setVal('geo-timezone', g.timezone || 'N/A');
  if (g.lat && g.lng) initMap(g.lat, g.lng);
}

function clearSkeletons() {
  document.querySelectorAll('.skeleton').forEach(el => {
    el.classList.remove('skeleton');
    if (!el.textContent.trim()) el.textContent = 'N/A';
  });
}

function initMap(lat, lng) {
  const map = L.map('map', { zoomControl: true, attributionControl: false, scrollWheelZoom: false })
    .setView([lat, lng], 11);
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 18 }).addTo(map);
  L.circleMarker([lat, lng], {
    radius: 10, fillColor: '#3b82f6', color: '#3b82f6',
    weight: 2, opacity: 0.8, fillOpacity: 0.3,
  }).addTo(map);
  window._netscopeMap = map;
  setTimeout(() => map.invalidateSize(), 400);
}

// ============================================================
// SPEED TEST - Multi-connection, time-based (Ookla-style)
// ============================================================
// Every request runs under a deadline tied to speedController, so a stalled
// connection ends the phase and Cancel stops the run at once. The timing logic
// lives in core.js (measureLatency, runTransferPhase) and is unit tested.
let speedRunning = false;
let speedController = null;

const SPEED_START_ICON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18" aria-hidden="true"><polygon points="5 3 19 12 5 21 5 3"/></svg>';

function setSpeedProgress(pct) {
  const fill = document.getElementById('speed-progress-fill');
  const text = document.getElementById('speed-progress-text');
  if (fill) fill.style.width = Math.round(pct) + '%';
  if (text) text.textContent = Math.round(pct) + '%';
}

function cancelSpeedTest() {
  if (speedController) speedController.abort(Core.speedAbortReason('cancelled'));
}

/** Runs latency, download and upload. Resolves with { status, message } from Core.summarizeSpeedRun. */
async function runSpeedTest() {
  if (speedRunning) return null;
  speedRunning = true;
  speedController = new AbortController();
  const signal = speedController.signal;
  const btn = document.getElementById('btn-speed-test');
  const cancelBtn = document.getElementById('btn-speed-cancel');
  const phase = document.getElementById('speed-phase');
  const ring = document.getElementById('gauge-ring');
  const progressWrap = document.getElementById('speed-progress-wrap');
  const note = document.getElementById('speed-note');
  btn.classList.add('hidden');
  cancelBtn.classList.remove('hidden');
  cancelBtn.disabled = false;
  cancelBtn.focus();
  ring.classList.add('active');
  phase.classList.add('active');
  phase.classList.remove('speed-phase--warn', 'speed-phase--error');
  note.innerHTML = '';
  if (progressWrap) progressWrap.style.display = '';
  setSpeedProgress(0);
  resetGauge();
  state.speed = { ping: null, jitter: null, download: null, upload: null, status: null };
  const phases = {};

  try {
    // LATENCY + JITTER
    phase.textContent = 'Testing latency...';
    setSpeedProgress(2);
    const latency = await testLatency(signal);
    phases.latency = { status: latency.status, measured: latency.samples.length > 0 };
    if (latency.samples.length) {
      const { ping, jitter } = Core.summarizeLatency(latency.samples);
      state.speed.ping = ping;
      state.speed.jitter = jitter;
      animateNumber(document.getElementById('speed-ping'), ping, 0);
      animateNumber(document.getElementById('speed-jitter'), jitter, 1);
    }
    setSpeedProgress(15);
    // No ping got through: the network or the test servers are unreachable, so skip the transfers.
    const reachable = latency.status !== 'failed';

    // DOWNLOAD (multi-connection, ~12s)
    if (reachable && !signal.aborted) {
      phase.textContent = 'Testing download...';
      const dl = await testMultiDownload(signal, pct => setSpeedProgress(15 + pct * 0.42));
      phases.download = { status: dl.status, measured: dl.mbps !== null };
      if (dl.mbps !== null) {
        state.speed.download = dl.mbps;
        animateNumber(document.getElementById('speed-download'), dl.mbps, 1);
        setGauge(dl.mbps);
        animateNumber(document.getElementById('gauge-number'), dl.mbps, 1);
      }
      setSpeedProgress(57);
    }

    // UPLOAD (multi-connection, ~12s)
    if (reachable && !signal.aborted) {
      phase.textContent = 'Testing upload...';
      const ul = await testMultiUpload(signal, pct => setSpeedProgress(57 + pct * 0.42));
      phases.upload = { status: ul.status, measured: ul.mbps !== null };
      if (ul.mbps !== null) {
        state.speed.upload = ul.mbps;
        animateNumber(document.getElementById('speed-upload'), ul.mbps, 1);
      }
    }
  } catch (err) {
    // The phases handle their own failures; this only catches programming errors.
    console.error('Speed test error:', err);
    phases.error = { status: 'failed', measured: false };
  }

  const summary = Core.summarizeSpeedRun(phases);
  state.speed.status = summary.status;
  if (summary.status === 'complete') {
    phase.textContent = summary.message;
  } else {
    phase.textContent = summary.status === 'cancelled' ? 'Test cancelled' : summary.status === 'failed' ? 'Test failed' : 'Partial results';
    phase.classList.add(summary.status === 'failed' ? 'speed-phase--error' : 'speed-phase--warn');
    note.innerHTML = statusHtml(summary.message, summary.status === 'failed' ? 'error' : 'warn');
  }
  setSpeedProgress(summary.status === 'complete' ? 100 : 0);
  if (progressWrap && summary.status !== 'complete') progressWrap.style.display = 'none';

  speedRunning = false;
  speedController = null;
  const hadFocus = document.activeElement === cancelBtn;
  cancelBtn.classList.add('hidden');
  btn.classList.remove('hidden');
  btn.innerHTML = `${SPEED_START_ICON} ${summary.status === 'complete' ? 'Run Again' : 'Try Again'}`;
  if (hadFocus) btn.focus();
  ring.classList.remove('active');
  phase.classList.remove('active');
  return summary;
}

/** One request under its own deadline that also stops when the run is cancelled. */
async function speedFetch(url, init, signal, timeoutMs) {
  const deadline = Core.createDeadline(timeoutMs, { signal });
  try {
    return await Core.raceAbort(fetch(url, { ...init, cache: 'no-store', signal: deadline.signal }), deadline.signal);
  } finally {
    deadline.clear();
  }
}

async function testLatency(signal) {
  // Warmup ping
  try { await speedFetch(`https://speed.cloudflare.com/__down?measId=warmup&bytes=0`, {}, signal, 3000); } catch {}

  return Core.measureLatency({
    signal,
    count: 20,
    pingTimeoutMs: 2000,
    totalMs: 8000,
    ping: async (i, pingSignal) => {
      try {
        await fetch(`https://speed.cloudflare.com/__down?measId=${Date.now()}-p${i}&bytes=0`, { cache: 'no-store', signal: pingSignal });
      } catch (err) {
        if (pingSignal.aborted) throw err;
        await fetch(`https://www.google.com/generate_204?_=${Date.now()}-${i}`, { mode: 'no-cors', cache: 'no-store', signal: pingSignal });
      }
    },
  });
}

async function testCfAvailable(signal) {
  try {
    const r = await speedFetch(`https://speed.cloudflare.com/__down?measId=${Date.now()}&bytes=1000`, {}, signal, 5000);
    return r.ok;
  } catch { return false; }
}

function showLiveSpeed(mbps) {
  setGauge(mbps);
  animateNumber(document.getElementById('gauge-number'), mbps, 1);
}

async function testMultiDownload(signal, onProgress) {
  const cfWorks = await testCfAvailable(signal);
  if (signal.aborted) return { mbps: null, status: 'cancelled' };
  if (!cfWorks) return await fallbackDownload(signal);

  return Core.runTransferPhase({
    signal,
    onProgress,
    onSample: showLiveSpeed,
    maxSize: 25000000,
    transfer: async (size, id, transferSignal) => {
      const r = await fetch(`https://speed.cloudflare.com/__down?measId=${Date.now()}-d${id}&bytes=${size}`, { cache: 'no-store', signal: transferSignal });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const buf = await r.arrayBuffer();
      return buf.byteLength;
    },
  });
}

/** Smaller files from a CDN when the Cloudflare speed endpoint is blocked. Each request has a 5 second deadline. */
async function fallbackDownload(signal) {
  const urls = [
    { url: 'https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js', size: 71000 },
    { url: 'https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js', size: 640000 },
  ];
  let bestSpeed = null;
  let stalled = false;
  for (const { url } of urls) {
    for (let attempt = 0; attempt < 3 && !signal.aborted; attempt++) {
      try {
        const start = performance.now();
        const r = await speedFetch(`${url}?_=${Date.now()}-${attempt}`, {}, signal, 5000);
        const buf = await r.arrayBuffer();
        const secs = (performance.now() - start) / 1000;
        const mbps = (buf.byteLength * 8) / secs / 1e6;
        if (bestSpeed === null || mbps > bestSpeed) bestSpeed = mbps;
        showLiveSpeed(mbps);
      } catch { stalled = true; break; }
    }
  }
  const kind = Core.abortKind(signal);
  const status = kind === 'cancelled' ? 'cancelled' : bestSpeed === null ? 'failed' : stalled ? 'partial' : 'complete';
  return { mbps: bestSpeed, status };
}

async function testMultiUpload(signal, onProgress) {
  return Core.runTransferPhase({
    signal,
    onProgress,
    maxSize: 10000000,
    transfer: async (size, id, transferSignal) => {
      const data = new Blob([new ArrayBuffer(size)]);
      const r = await fetch('https://speed.cloudflare.com/__up', { method: 'POST', body: data, cache: 'no-store', signal: transferSignal });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return size;
    },
  });
}

function resetGauge() {
  document.getElementById('gauge-circle').style.strokeDashoffset = String(Core.GAUGE_CIRCUMFERENCE);
  document.getElementById('gauge-number').textContent = '0';
  document.getElementById('speed-ping').textContent = '--';
  document.getElementById('speed-jitter').textContent = '--';
  document.getElementById('speed-download').textContent = '--';
  document.getElementById('speed-upload').textContent = '--';
}

function setGauge(mbps) {
  document.getElementById('gauge-circle').style.strokeDashoffset = Core.gaugeDashOffset(mbps);
}

function animateNumber(el, target, decimals = 1, duration = 600) {
  const start = parseFloat(el.textContent) || 0;
  const startTime = performance.now();
  function tick(now) {
    const t = Math.min((now - startTime) / duration, 1);
    const eased = 1 - Math.pow(1 - t, 3); // ease-out cubic
    el.textContent = (start + (target - start) * eased).toFixed(decimals);
    if (t < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

// ============================================================
// BREACH CHECK - EMAIL (XposedOrNot + HIBP link)
// ============================================================
async function checkEmailBreach() {
  const email = document.getElementById('email-input').value.trim();
  if (!Core.isPlausibleEmail(email)) {
    showToast('Enter a valid email address');
    return;
  }
  const resultEl = document.getElementById('email-result');
  const btn = document.getElementById('btn-email-check');
  btn.disabled = true;
  setBusy(resultEl, 'Checking breaches...');

  const result = await Core.checkEmailExposure(email, { fetchImpl: timedFetch });
  const hibpUrl = `https://haveibeenpwned.com/account/${encodeURIComponent(email)}`;
  const breaches = result.breaches;

  if (result.status === 'found') {
    resultEl.innerHTML = `
      <div class="result-card result-card--danger">
        ${ICON_DANGER}
        <div class="result-title">Found in ${breaches.length} breach${breaches.length > 1 ? 'es' : ''}</div>
        <div class="result-sub">This email has appeared in known data breaches.</div>
      </div>
      <div class="breach-list">
        ${breaches.map(b => `<div class="breach-item"><div class="breach-item-name">${esc(b.name)}</div>${b.domain ? `<div class="breach-item-domain">${esc(b.domain)}</div>` : ''}</div>`).join('')}
      </div>
      <a href="${esc(hibpUrl)}" target="_blank" rel="noopener noreferrer" class="hibp-link">View full details on Have I Been Pwned</a>
    `;
  } else if (result.status === 'clean') {
    resultEl.innerHTML = `
      <div class="result-card result-card--safe">
        ${ICON_SAFE}
        <div class="result-title">No breaches found</div>
        <div class="result-sub">This email wasn't found in our breach database check.</div>
      </div>
      <a href="${esc(hibpUrl)}" target="_blank" rel="noopener noreferrer" class="hibp-link">Double-check on Have I Been Pwned</a>
    `;
  } else {
    const reason = result.httpStatus === 429 ? 'The breach service is rate limiting requests. Wait a few minutes and try again.' : 'The breach service could not be reached, so no result is shown.';
    resultEl.innerHTML = `
      <div class="result-card result-card--warn">
        ${ICON_WARN}
        <div class="result-title">Check did not complete</div>
        <div class="result-sub">${esc(reason)}</div>
      </div>
      <a href="${esc(hibpUrl)}" target="_blank" rel="noopener noreferrer" class="hibp-link">Check on Have I Been Pwned instead</a>
    `;
  }

  state.breach.email = { email, found: result.status === 'found', status: result.status, count: breaches.length };
  resultEl.setAttribute('aria-busy', 'false');
  btn.disabled = false;
}

// ============================================================
// BREACH CHECK - PASSWORD (HIBP k-anonymity)
// ============================================================
async function checkPasswordBreach() {
  const input = document.getElementById('password-input');
  const password = input.value;
  if (!password) { showToast('Enter a password to check'); return; }

  const resultEl = document.getElementById('password-result');
  const btn = document.getElementById('btn-password-check');
  btn.disabled = true;
  setBusy(resultEl, 'Checking...');

  try {
    // Only the first 5 characters of the SHA-1 hash leave the browser.
    const { count } = await Core.checkPwnedPassword(password, { fetchImpl: timedFetch });
    const summary = Core.passwordCheckSummary(password, count);
    const strengthLine = `<div class="result-sub">Estimated strength: ${esc(summary.strength.label)} (${summary.strength.score} of 5)</div>`;
    if (count === 0) {
      resultEl.innerHTML = `
        <div class="result-card result-card--safe">
          ${ICON_SAFE}
          <div class="result-title">Not found in any breaches</div>
          <div class="result-sub">This password hasn't appeared in known data breaches. Still use unique passwords everywhere.</div>
          ${strengthLine}
        </div>`;
    } else {
      resultEl.innerHTML = `
        <div class="result-card result-card--danger">
          ${ICON_DANGER}
          <div class="result-title">Found ${esc(count.toLocaleString())} times</div>
          <div class="result-sub">This password has been seen in data breaches. Change it immediately and never reuse it.</div>
          ${strengthLine}
        </div>`;
    }
    // Keep only found or not found and the strength score for the report.
    // The password, its hash and the breach count are never stored or exported.
    state.breach.password = summary;
  } catch (err) {
    console.error('Password check error:', err.message);
    state.breach.password = null;
    resultEl.innerHTML = statusHtml('Could not reach the breach service, so no result is shown. Check your connection and try again.', 'error');
  }
  resultEl.setAttribute('aria-busy', 'false');
  btn.disabled = false;
}

// ============================================================
// DNS & SECURITY SCAN
// ============================================================
async function dohQuery(name, type, extra = '') {
  const r = await timedFetch(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}${extra}`, { referrerPolicy: 'no-referrer' });
  if (!r.ok) throw new Error(`DNS query failed with HTTP ${r.status}`);
  return r.json();
}

const CHECK_GLYPHS = { pass: '&#x2713;', fail: '&#x2717;', warn: '!', info: 'i' };
const CHECK_LABELS = { pass: 'Pass', fail: 'Fail', warn: 'Warning', info: 'Info' };

function renderCheck(c) {
  const icon = CHECK_GLYPHS[c.icon] ? c.icon : 'info';
  return `<div class="security-check">
      <div class="check-icon check-icon--${icon}" role="img" aria-label="${CHECK_LABELS[icon]}">${CHECK_GLYPHS[icon]}</div>
      <div>
        <div class="check-name">${esc(c.name)}</div>
        <div class="check-detail">${esc(c.detail)}</div>
        ${c.value ? `<div class="check-value">${esc(c.value)}</div>` : ''}
        ${c.explain ? `<div class="check-explain">${esc(c.explain)}</div>` : ''}
        ${c.fix && c.icon !== 'pass' ? `<div class="check-fix"><strong>How to fix:</strong> ${esc(c.fix)}</div>` : ''}
      </div>
    </div>`;
}

async function runDNSScan() {
  const raw = document.getElementById('scan-input').value.trim();
  if (!raw) { showToast('Enter a domain or email'); return; }

  const domain = Core.normalizeDomainInput(raw);
  if (!domain) { showToast('Enter a valid domain, URL, or email address'); return; }

  const btn = document.getElementById('btn-scan');
  const resultsEl = document.getElementById('scan-results');
  btn.disabled = true;
  btn.textContent = 'Scanning...';
  setBusy(resultsEl, `Scanning ${domain}...`);

  try {
    const result = await Core.scanDomain(domain, dohQuery);

    if (result.status === 'nxdomain') {
      state.scan = null;
      resultsEl.innerHTML = statusHtml(`${domain} does not exist in DNS. Check the spelling and try again.`, 'warn');
      return;
    }
    if (result.status === 'error') {
      state.scan = null;
      resultsEl.innerHTML = statusHtml('Could not reach the DNS service, so no result is shown. Check your connection and try again.', 'error');
      return;
    }

    const checks = result.checks.slice();
    try {
      checks.push(Core.evaluateWebRtc(Core.classifyIceCandidates(await collectIceCandidates()), state.ip));
    } catch {}
    checks.push({
      icon: location.protocol === 'https:' ? 'pass' : 'fail',
      name: 'Your Connection',
      detail: location.protocol === 'https:' ? 'You are browsing this page over HTTPS' : 'Not using HTTPS',
    });
    state.scan = { domain, checks };

    const summary = Core.summarizeChecks(result.checks);
    const grade = Core.gradeChecks(result.checks);
    const lost = grade.deductions.map(d => `${d.name} (${d.points})`).join(', ');
    let html = `<div class="scan-summary scan-summary--${summary.verdict}">
      <div class="scan-grade scan-grade--${grade.grade.toLowerCase()}" role="img" aria-label="Grade ${grade.grade}">${grade.grade}</div>
      <div class="scan-summary-body">
        <div class="scan-summary-title">${esc(domain)}: ${esc(summary.label)}</div>
        <div class="scan-summary-text">${esc(grade.summary)}</div>
        <div class="scan-summary-counts">Score ${grade.score} of 100. ${summary.pass} passed, ${summary.warn} warnings, ${summary.fail} failed, ${summary.info} informational.${lost ? ` Points lost: ${esc(lost)}.` : ''}${grade.incomplete ? ' Some checks could not be looked up, so the grade may be incomplete.' : ''}</div>
      </div>
    </div>`;

    html += '<div class="scan-section"><h3 class="scan-section-title">DNS Records</h3>';
    if (result.records.length === 0) {
      html += statusHtml('No A, AAAA, MX or NS records were returned for this name.', 'empty');
    }
    for (const rec of result.records) {
      html += `<div class="dns-record">
          <span class="dns-record-type">${esc(rec.type)}</span>
          <span class="dns-record-value">${esc(rec.data)}</span>
          <span class="dns-record-ttl">TTL ${esc(rec.ttl)}s</span>
        </div>`;
    }
    if (result.failedLookups > 0) {
      html += statusHtml(`${result.failedLookups} record lookup${result.failedLookups > 1 ? 's' : ''} failed, so this list may be incomplete.`, 'warn');
    }
    html += '</div>';

    html += '<div class="scan-section"><h3 class="scan-section-title">Email Security</h3>';
    html += result.checks.map(renderCheck).join('');
    html += '</div>';

    html += '<div class="scan-section"><h3 class="scan-section-title">Your Browser</h3>';
    html += checks.slice(result.checks.length).map(renderCheck).join('');
    html += '</div>';

    resultsEl.innerHTML = html;
  } catch (err) {
    console.error('DNS scan error:', err);
    resultsEl.innerHTML = statusHtml('The scan stopped unexpectedly. No result is shown. Try again.', 'error');
  } finally {
    resultsEl.setAttribute('aria-busy', 'false');
    btn.disabled = false;
    btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16" aria-hidden="true"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg> Scan';
  }
}

/** Gather ICE candidate lines for up to 3 seconds. */
function collectIceCandidates() {
  return new Promise(resolve => {
    const candidates = [];
    let pc;
    const finish = () => { try { pc && pc.close(); } catch {} resolve(candidates); };
    try {
      pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
      pc.createDataChannel('');
      pc.onicecandidate = e => {
        if (!e.candidate) { finish(); return; }
        if (e.candidate.candidate) candidates.push(e.candidate.candidate);
      };
      pc.createOffer().then(o => pc.setLocalDescription(o)).catch(finish);
      setTimeout(finish, 3000);
    } catch { resolve(candidates); }
  });
}

// ============================================================
// EXPORT
// ============================================================
function buildText() {
  return Core.buildTextReport(state);
}

function exportCopy() {
  navigator.clipboard.writeText(buildText()).then(() => showToast('Copied to clipboard')).catch(() => showToast('Copy failed'));
  document.getElementById('export-panel').classList.remove('open');
}

function exportEmail() {
  const s = encodeURIComponent('NetScope Results');
  const b = encodeURIComponent(buildText());
  window.open(`mailto:?subject=${s}&body=${b}`, '_self');
  document.getElementById('export-panel').classList.remove('open');
}

function exportPDF() {
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();
  const text = buildText();
  const lines = doc.splitTextToSize(text, 170);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(18);
  doc.setTextColor(59, 130, 246);
  doc.text('NetScope Report', 20, 20);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(120, 120, 120);
  doc.text(new Date().toLocaleString(), 20, 27);
  doc.setDrawColor(220, 220, 220);
  doc.line(20, 30, 190, 30);
  doc.setFontSize(10);
  doc.setTextColor(40, 40, 40);
  let y = 38;
  for (const line of lines) {
    if (y > 280) { doc.addPage(); y = 20; }
    if (line.startsWith('---')) {
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(59, 130, 246);
      doc.text(line.replace(/---/g, '').trim(), 20, y);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(40, 40, 40);
    } else {
      doc.text(line, 20, y);
    }
    y += 5.5;
  }
  doc.save('netscope-report.pdf');
  showToast('PDF downloaded');
  document.getElementById('export-panel').classList.remove('open');
}

// ============================================================
// UTILITIES
// ============================================================
function setVal(id, val) {
  const el = document.getElementById(id);
  el.textContent = val;
  el.classList.remove('skeleton');
}

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2500);
}

// Escapes &, <, >, " and ' so values are safe in text and quoted attributes.
const esc = Core.escapeHtml;

// Every third-party call gets a deadline so a stalled provider shows an error instead of spinning forever.
const timedFetch = (url, init) => Core.fetchWithTimeout(url, init, { timeoutMs: 10000 });

/** One markup pattern for loading, empty, warning and error states across the tools. */
function statusHtml(message, kind = 'loading') {
  const role = kind === 'error' ? ' role="alert"' : '';
  return `<div class="tool-status tool-status--${esc(kind)}"${role}>${esc(message)}</div>`;
}

function setBusy(el, message) {
  el.setAttribute('aria-busy', 'true');
  el.innerHTML = statusHtml(message, 'loading');
}

const ICON_DANGER = '<div class="result-icon result-icon--danger" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="36" height="36"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg></div>';
const ICON_SAFE = '<div class="result-icon result-icon--safe" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="36" height="36"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg></div>';
const ICON_WARN = '<div class="result-icon result-icon--warn" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="36" height="36"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg></div>';

// ============================================================
// THEME
// ============================================================
function initTheme() {
  // Theme already set by inline script in <head>, but bind toggle
  document.getElementById('theme-toggle')?.addEventListener('click', toggleTheme);
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  const next = current === 'dark' ? 'light' : 'dark';
  applyTheme(next);
  localStorage.setItem('netscope-theme', next);
  updateSettingsThemeLabel();
  // Sync to Firebase if logged in
  if (typeof currentUser !== 'undefined' && currentUser && typeof saveUserPreferences === 'function') {
    saveUserPreferences({ theme: next });
  }
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  // Update mobile menu label
  const label = document.getElementById('mobile-theme-label');
  if (label) label.textContent = theme === 'dark' ? 'Light Mode' : 'Dark Mode';
}

// ============================================================
// MOBILE MENU
// ============================================================
function initMobileMenu() {
  const hamburger = document.getElementById('hamburger');
  const drawer = document.getElementById('mobile-menu');
  const backdrop = document.getElementById('drawer-backdrop');
  const closeBtn = document.getElementById('drawer-close');
  if (!hamburger || !drawer) return;

  function openDrawer() {
    drawer.classList.add('open');
    backdrop?.classList.add('open');
    hamburger.classList.add('open');
    hamburger.setAttribute('aria-expanded', 'true');
    document.body.style.overflow = 'hidden';
    closeBtn?.focus();
    document.addEventListener('keydown', handleDrawerEscape);
  }

  function closeDrawer() {
    drawer.classList.remove('open');
    backdrop?.classList.remove('open');
    hamburger.classList.remove('open');
    hamburger.setAttribute('aria-expanded', 'false');
    document.body.style.overflow = '';
    document.removeEventListener('keydown', handleDrawerEscape);
    hamburger.focus();
  }

  function handleDrawerEscape(e) {
    if (e.key === 'Escape') closeDrawer();
  }

  hamburger.addEventListener('click', () => {
    drawer.classList.contains('open') ? closeDrawer() : openDrawer();
  });

  backdrop?.addEventListener('click', closeDrawer);
  closeBtn?.addEventListener('click', closeDrawer);

  // Close drawer when a nav link is clicked
  drawer.querySelectorAll('.mobile-nav-link[href]').forEach(link => {
    link.addEventListener('click', closeDrawer);
  });

  // Focus trap within drawer
  drawer.addEventListener('keydown', (e) => {
    if (e.key !== 'Tab') return;
    const focusable = drawer.querySelectorAll(
      'a[href], button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])'
    );
    if (focusable.length === 0) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  });

  // Mobile theme toggle
  document.getElementById('mobile-theme-toggle')?.addEventListener('click', toggleTheme);
}

// ============================================================
// LOADING SCREEN
// ============================================================
function dismissLoadingScreen() {
  const fontPromise = document.fonts ? document.fonts.ready : Promise.resolve();
  const timeout = new Promise(resolve => setTimeout(resolve, 3000));

  Promise.race([fontPromise, timeout]).then(() => {
    setTimeout(() => {
      const screen = document.getElementById('loading-screen');
      if (screen) {
        screen.classList.add('hidden');
        screen.addEventListener('transitionend', () => screen.remove(), { once: true });
      }
    }, 300);
  });
}

// ============================================================
// PASSWORD GENERATOR
// ============================================================
const CHARSETS = Core.CHARSETS;

const WORDLIST = [
  'absorb','accent','acid','acorn','acre','adapt','adjust','admit','adult','advice',
  'afford','agent','agree','ahead','alarm','album','alert','alien','align','alive',
  'alpha','amaze','ample','anchor','angel','angle','angry','animal','ankle','annual',
  'apart','appeal','apple','arena','argue','armor','army','arrow','artist','ascend',
  'aspect','asset','assist','atom','audio','audit','august','avid','avoid','awake',
  'badge','bamboo','banana','banner','barrel','basic','basket','battle','beach','beacon',
  'beast','beauty','beetle','begin','behave','belly','bench','best','beyond','bike',
  'bind','bitter','blade','blame','blank','blast','blaze','bleed','blend','bless',
  'blind','block','bloom','board','bold','bolt','bomb','bonus','boost','border',
  'bounce','brain','brave','bread','breeze','brick','bridge','brief','bright','broad',
  'broken','bronze','brush','bubble','budget','build','bullet','bundle','burden','burst',
  'cabin','cable','cage','calm','camera','camp','canal','candle','cannon','canvas',
  'carbon','cargo','carpet','castle','casual','catch','cattle','causal','cave','cedar',
  'cellar','cement','census','cereal','chain','chair','chalk','champ','change','chapel',
  'charge','charm','chase','cheap','check','cherry','chess','chief','child','chunk',
  'circle','civil','claim','clamp','clash','class','clean','clever','click','cliff',
  'climb','clinic','clock','close','cloth','cloud','cluster','coach','coast','cobalt',
  'code','coffee','coil','cold','collar','column','combat','comedy','commit','common',
  'copper','coral','corner','cosmic','cotton','couch','cover','craft','crane','crash',
  'crater','crawl','crazy','cream','credit','creek','crest','crew','crisis','crisp',
  'cross','crowd','cruel','crush','crystal','cubic','cupid','curve','cycle','dagger',
  'daily','damage','dance','danger','daring','dash','dawn','debate','decade','decent',
  'decide','deep','defend','define','defy','delay','delta','demand','demon','denial',
  'dense','deny','deploy','depth','deputy','derive','desert','design','detail','detect',
  'device','devote','dialog','diesel','differ','digit','dinner','direct','dirty','disco',
  'divide','dizzy','doctor','dodge','domain','donor','double','draft','dragon','drama',
  'drastic','dream','dress','drift','drill','drink','drive','drop','drum','dry',
  'dune','dust','duty','dwarf','dynamic','eager','eagle','earth','echo','eclipse',
  'edge','effort','eight','elbow','elder','elect','elegant','elite','embark','ember',
  'emerge','emit','empire','employ','empty','enable','endure','enemy','energy','engine',
  'enjoy','enrich','ensure','entire','entry','envy','episode','equal','equip','erode',
  'error','escape','estate','eternal','evade','evening','evolve','exact','example','excess',
  'exotic','expand','expect','expire','export','expose','extend','extra','fable','fabric',
  'factor','faculty','faint','faith','false','family','famous','fancy','fantasy','fatal',
  'father','fault','feast','federal','fence','festival','fetch','fever','fiber','fiction',
  'field','figure','filter','final','finger','finish','fire','firm','fiscal','flag',
  'flame','flash','flavor','fleet','flight','float','flood','floor','flower','fluid',
  'foam','focus','foil','fold','follow','food','force','forest','forget','formal',
  'fossil','foster','found','fragile','frame','fresh','friend','fringe','frog','frozen',
  'fruit','fuel','fury','future','gadget','galaxy','garden','garlic','gate','gauge',
  'gaze','general','genius','genre','gentle','ghost','giant','gift','ginger','glad',
  'glance','glass','globe','glory','glove','glow','goat','gospel','gossip','govern',
  'grace','grain','grant','grape','gravity','great','green','grid','grief','grit',
  'group','guard','guess','guide','guitar','habit','hammer','happy','harbor','harvest',
  'hawk','hazard','health','heart','heavy','helmet','hero','hidden','highway','hockey',
  'hollow','home','honey','honor','horror','horse','host','hotel','hover','human',
  'humble','humor','hunger','hybrid','ice','icon','idea','ignore','image','immune',
  'impact','import','impose','impulse','income','index','indoor','infant','inflict','inform',
  'inject','inmate','inner','input','insect','inside','insist','install','intact','invite',
  'iron','island','isolate','ivory','jacket','jaguar','jazz','jewel','job','joint',
  'joke','journal','journey','judge','juice','jumbo','jungle','junior','just','kangaroo',
  'kayak','keeper','kernel','kettle','kidney','kingdom','kitchen','kiwi','knee','knife',
  'knock','label','labor','ladder','lance','laptop','large','laser','latch','launch',
  'lava','lawn','layer','leader','leaf','legacy','legend','lemon','length','lens',
  'letter','level','liberty','light','limit','linger','lion','liquid','list','little',
  'lizard','load','lobster','local','logic','lonely','loop','lottery','loyal','lucky',
  'lumber','lunar','lunch','luxury','lyrics','magnet','maiden','major','mango','maple',
  'marble','margin','marine','master','match','matter','meadow','media','melody','member',
  'mental','mentor','mercy','merge','merit','method','middle','mild','million','mimic',
  'mineral','minor','minute','mirror','misery','mix','mobile','model','modify','moist',
  'moment','monkey','monster','month','moral','motion','motor','mouse','movie','muffin',
  'muscle','museum','music','mutual','mystery','myth','naive','napkin','narrow','nasty',
  'nature','near','needle','nerve','nest','neutral','noble','noise','nomad','normal',
  'notice','novel','number','nurse','object','obtain','ocean','offer','olive','omega',
  'onion','open','opera','opinion','oppose','option','orbit','orange','order','organ',
  'orient','orphan','ostrich','outer','output','oval','owner','oxygen','oyster','ozone',
  'paddle','palace','panda','panel','panic','paper','parade','parent','parrot','patch',
  'patrol','pause','peanut','pelican','pencil','people','pepper','perfect','permit','person',
  'phrase','piano','picnic','picture','piece','pilot','pistol','pizza','planet','plaster',
  'plaza','pledge','plunge','pocket','poem','polar','police','pond','pony','popular',
  'portal','potato','pottery','poverty','powder','power','predict','prepare','present','pretty',
  'prevent','pride','primary','prince','prison','private','problem','process','profit','program',
  'project','promise','protect','provide','public','pudding','pulse','pumpkin','punch','purple',
  'puzzle','pyramid','quantum','quarter','queen','quick','quote','rabbit','radar','radio',
  'raise','rally','ramp','random','range','rapid','rather','raven','razor','rebel',
  'recall','record','recycle','reform','region','regret','regular','reject','relax','release',
  'relief','remain','remind','remove','render','renew','repair','repeat','replace','report',
  'rescue','resist','result','retire','retreat','return','reveal','review','reward','ribbon',
  'rifle','rigid','ring','ripple','ritual','river','road','robot','rocket','romance',
  'rotate','rough','royal','rubber','rude','rugby','ruler','runway','rural','saddle',
  'sadness','safari','salad','salmon','salon','salute','sample','satisfy','sauce','sausage',
  'scale','scatter','scene','scheme','school','scout','screen','script','search','season',
  'second','secret','section','segment','select','senior','sense','series','service','session',
  'settle','shadow','shaft','shallow','sheriff','shield','shift','shock','shrimp','shrug',
  'shuttle','sibling','siege','sight','signal','silent','silver','simple','since','siren',
  'sister','sketch','skull','slender','slice','slim','slogan','slow','small','smart',
  'smile','smooth','snake','soccer','social','sodium','solar','solid','solution','source',
  'space','spare','spatial','spawn','spend','sphere','spider','spirit','splash','split',
  'sponsor','spray','spread','spring','squad','squeeze','stable','stadium','staff','stage',
  'stairs','stamp','stand','start','steak','steel','stem','stereo','stick','stone',
  'storm','story','strategy','street','strike','strong','struggle','student','studio','style',
  'submit','sudden','sugar','summer','summit','sunset','super','supply','surface','surge',
  'surprise','survey','suspect','sustain','swamp','swift','symbol','symptom','system','table',
  'tackle','talent','target','temple','tenant','tender','tennis','term','test','theme',
  'theory','thesis','thrill','throne','tiger','timber','tissue','title','toast','today',
  'tomato','tongue','topple','total','tourist','tower','traffic','train','transfer','travel',
  'tray','trend','trial','tribe','trick','trigger','trim','triple','trophy','trouble',
  'truck','truly','trumpet','trust','tumble','tunnel','turkey','twist','typical','ugly',
  'umbrella','unable','uncle','under','unfair','unfold','unique','unit','universe','unknown',
  'unlock','until','unveil','update','upgrade','upper','upset','urban','usage','useful',
  'usual','utility','vacant','vacuum','valley','valve','vanish','vapor','vast','vault',
  'vehicle','velvet','vendor','venture','verify','version','vessel','veteran','viable','victim',
  'victory','video','village','vintage','violin','virtual','virus','visit','visual','vital',
  'vivid','vocal','voice','volcano','volume','voyage','waffle','wagon','walnut','wander',
  'warrior','water','wealth','weapon','weather','wedding','welcome','whale','wheat','whisper',
  'wicked','wide','wisdom','witness','wolf','wonder','world','worry','worth','wrap',
  'wreck','wrestle','wrist','yard','yellow','yoga','young','zebra','zero','zone'
];

let currentPreset = 'password';

function initPasswordGenerator() {
  const slider = document.getElementById('pwgen-length');
  const lengthVal = document.getElementById('pwgen-length-val');
  slider.addEventListener('input', () => { lengthVal.textContent = slider.value; });

  document.getElementById('btn-generate').addEventListener('click', generatePassword);
  document.getElementById('pwgen-copy').addEventListener('click', copyPassword);

  // Preset buttons
  document.querySelectorAll('.pwgen-preset').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.pwgen-preset').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentPreset = btn.dataset.preset;
      applyPreset(currentPreset);
      generatePassword();
    });
  });
}

function applyPreset(preset) {
  const controls = document.getElementById('pwgen-controls');
  const slider = document.getElementById('pwgen-length');
  const lengthVal = document.getElementById('pwgen-length-val');
  const genBtn = document.getElementById('btn-generate');

  if (preset === 'passphrase') {
    controls.classList.add('hidden');
    genBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg> Generate Passphrase';
  } else {
    controls.classList.remove('hidden');
    genBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg> Generate Password';

    if (preset === 'pin') {
      slider.min = 4; slider.max = 12; slider.value = 6;
      lengthVal.textContent = '6';
      document.getElementById('pwgen-upper').checked = false;
      document.getElementById('pwgen-lower').checked = false;
      document.getElementById('pwgen-numbers').checked = true;
      document.getElementById('pwgen-symbols').checked = false;
    } else if (preset === 'hex') {
      slider.min = 8; slider.max = 64; slider.value = 32;
      lengthVal.textContent = '32';
      document.getElementById('pwgen-upper').checked = false;
      document.getElementById('pwgen-lower').checked = false;
      document.getElementById('pwgen-numbers').checked = false;
      document.getElementById('pwgen-symbols').checked = false;
    } else { // password
      slider.min = 8; slider.max = 64; slider.value = 20;
      lengthVal.textContent = '20';
      document.getElementById('pwgen-upper').checked = true;
      document.getElementById('pwgen-lower').checked = true;
      document.getElementById('pwgen-numbers').checked = true;
      document.getElementById('pwgen-symbols').checked = true;
    }
  }
}

function generatePassword() {
  if (currentPreset === 'passphrase') {
    generatePassphrase();
    return;
  }

  const length = parseInt(document.getElementById('pwgen-length').value, 10);
  let pool = '';
  if (currentPreset === 'hex') {
    pool = CHARSETS.hex;
  } else {
    if (document.getElementById('pwgen-upper').checked) pool += CHARSETS.upper;
    if (document.getElementById('pwgen-lower').checked) pool += CHARSETS.lower;
    if (document.getElementById('pwgen-numbers').checked) pool += CHARSETS.numbers;
    if (document.getElementById('pwgen-symbols').checked) pool += CHARSETS.symbols;
  }

  if (!pool) {
    showToast('Select at least one character set');
    return;
  }

  // Rejection sampling in core.js keeps every character equally likely.
  const { value, entropyBits } = Core.generateFromPool(pool, length);
  document.getElementById('pwgen-password').textContent = value;
  updateStrength(entropyBits);
}

function generatePassphrase() {
  const { value, entropyBits } = Core.generatePassphrase(WORDLIST, 5, '-');
  document.getElementById('pwgen-password').textContent = value;
  updateStrength(entropyBits);
}

// Strength comes from how the value was generated (pool size and length, or
// word list size and word count), not from guessing at the output string.
function updateStrength(entropyBits) {
  const bar = document.getElementById('pwgen-strength-bar');
  const label = document.getElementById('pwgen-strength-label');
  const colors = {
    'weak': 'var(--accent-red)',
    'fair': 'var(--accent-orange)',
    'good': 'var(--accent-blue)',
    'strong': 'var(--accent-cyan)',
    'very-strong': 'var(--accent-green)',
  };
  const strength = Core.strengthFromEntropy(entropyBits);
  const color = colors[strength.level];

  bar.style.width = strength.percent + '%';
  bar.style.background = color;
  label.textContent = `${strength.label} (${Math.round(entropyBits)} bits of entropy)`;
  label.style.color = color;
}

function copyPassword() {
  const pw = document.getElementById('pwgen-password').textContent;
  if (!pw || pw === 'Your password will appear here') { showToast('Generate a password first'); return; }
  navigator.clipboard.writeText(pw)
    .then(() => showToast('Password copied'))
    .catch(() => showToast('Copy failed'));
}

// ============================================================
// FULL SECURITY SCAN
// ============================================================
let fullScanRunning = false;
let fullScanCancelled = false;

function initFullScan() {
  document.getElementById('btn-full-scan')?.addEventListener('click', startFullScan);
  document.getElementById('fullscan-cancel')?.addEventListener('click', cancelFullScan);
  document.getElementById('fullscan-view-results')?.addEventListener('click', closeFullScan);
}

function setFsStep(id, status, text) {
  const step = document.getElementById(id);
  const statusEl = document.getElementById(id + '-status');
  if (!step) return;
  step.className = 'fullscan-step' + (status === 'running' ? ' running' : status === 'done' ? ' done' : '');
  if (statusEl) statusEl.textContent = text;
}

function setFsProgress(pct) {
  const fill = document.getElementById('fullscan-bar-fill');
  const text = document.getElementById('fullscan-bar-text');
  if (fill) fill.style.width = pct + '%';
  if (text) text.textContent = Math.round(pct) + '%';
}

async function startFullScan() {
  if (fullScanRunning) return;
  fullScanRunning = true;
  fullScanCancelled = false;

  const overlay = document.getElementById('fullscan-overlay');
  const subtitle = document.getElementById('fullscan-subtitle');
  const actions = document.getElementById('fullscan-actions');
  const done = document.getElementById('fullscan-done');

  // Reset
  ['fs-ip', 'fs-speed', 'fs-breach', 'fs-dns'].forEach(id => setFsStep(id, '', 'Waiting'));
  setFsProgress(0);
  if (actions) actions.style.display = '';
  if (done) done.style.display = 'none';
  if (subtitle) subtitle.textContent = 'Initializing scan...';
  if (overlay) overlay.style.display = '';

  try {
    // 1. IP & Geolocation
    if (fullScanCancelled) return;
    setFsStep('fs-ip', 'running', 'Detecting IP...');
    if (subtitle) subtitle.textContent = 'Detecting your IP and location...';
    if (!ipFetched) {
      ipFetched = true;
      await fetchIPInfo();
    }
    setFsStep('fs-ip', 'done', 'Complete');
    setFsProgress(25);

    // 2. Speed Test
    if (fullScanCancelled) return;
    setFsStep('fs-speed', 'running', 'Testing connection...');
    if (subtitle) subtitle.textContent = 'Measuring network speed...';
    const speedSummary = speedRunning ? null : await runSpeedTest();
    const speedLabel = { cancelled: 'Cancelled', partial: 'Partial results', failed: 'Could not run' };
    setFsStep('fs-speed', 'done', (speedSummary && speedLabel[speedSummary.status]) || 'Complete');
    setFsProgress(60);

    // 3. Breach Check (autofill email if signed in)
    if (fullScanCancelled) return;
    setFsStep('fs-breach', 'running', 'Checking breaches...');
    if (subtitle) subtitle.textContent = 'Checking email breaches...';
    const emailInput = document.getElementById('email-input');
    const userEmail = (typeof currentUser !== 'undefined' && currentUser?.email) ? currentUser.email : '';
    if (userEmail && emailInput && !emailInput.value.trim()) {
      emailInput.value = userEmail;
    }
    if (emailInput && emailInput.value.trim()) {
      await checkEmailBreach();
      setFsStep('fs-breach', 'done', 'Complete');
    } else {
      await new Promise(r => setTimeout(r, 400));
      setFsStep('fs-breach', 'done', 'Skipped (no email)');
    }
    setFsProgress(80);

    // 4. DNS (skip if no domain - just mark done)
    if (fullScanCancelled) return;
    setFsStep('fs-dns', 'running', 'Checking DNS...');
    if (subtitle) subtitle.textContent = 'Scanning DNS security...';
    const scanInput = document.getElementById('scan-input')?.value.trim();
    if (scanInput) {
      await runDNSScan();
    } else {
      await new Promise(r => setTimeout(r, 400));
    }
    setFsStep('fs-dns', 'done', scanInput ? 'Complete' : 'Skipped (no domain)');
    setFsProgress(100);

    // Done
    if (subtitle) subtitle.textContent = 'Scan complete!';
    if (actions) actions.style.display = 'none';
    if (done) done.style.display = '';
  } catch (err) {
    console.error('Full scan error:', err);
    if (subtitle) subtitle.textContent = 'Scan completed with partial results';
    if (actions) actions.style.display = 'none';
    if (done) done.style.display = '';
  } finally {
    fullScanRunning = false;
  }
}

function cancelFullScan() {
  fullScanCancelled = true;
  fullScanRunning = false;
  closeFullScan();
}

function closeFullScan() {
  const overlay = document.getElementById('fullscan-overlay');
  if (overlay) overlay.style.display = 'none';
}

// ============================================================
// SETTINGS PANEL
// ============================================================
function initSettings() {
  document.getElementById('settings-theme-toggle')?.addEventListener('click', toggleTheme);

  document.getElementById('settings-clear-data')?.addEventListener('click', () => {
    localStorage.removeItem('netscope-theme');
    localStorage.removeItem('netscope-guest');
    localStorage.removeItem('netscope-session');
    showToast('Local data cleared');
  });

  document.getElementById('settings-sign-in')?.addEventListener('click', () => {
    closeSettingsPanel();
    if (typeof showAuthGate === 'function') showAuthGate();
  });

  document.getElementById('settings-sign-out')?.addEventListener('click', () => {
    closeSettingsPanel();
    if (typeof handleSignOut === 'function') handleSignOut();
  });

  document.getElementById('settings-panel-close')?.addEventListener('click', closeSettingsPanel);

  // Close on backdrop click
  document.getElementById('settings-panel')?.addEventListener('click', e => {
    if (e.target.id === 'settings-panel') closeSettingsPanel();
  });

  // Fallback settings triggers (work without Firebase)
  document.getElementById('btn-settings')?.addEventListener('click', () => { openSettingsPanel(); });
  document.getElementById('mobile-btn-settings')?.addEventListener('click', () => {
    openSettingsPanel();
    if (typeof closeMobileMenu === 'function') closeMobileMenu();
  });

  updateSettingsThemeLabel();
}

function openSettingsPanel() {
  document.getElementById('settings-panel')?.classList.add('open');
  document.body.style.overflow = 'hidden';
}

function closeSettingsPanel() {
  document.getElementById('settings-panel')?.classList.remove('open');
  document.body.style.overflow = '';
}

function updateSettingsThemeLabel() {
  const label = document.getElementById('settings-theme-label');
  if (label) {
    const current = document.documentElement.getAttribute('data-theme') || 'dark';
    label.textContent = current === 'dark' ? 'Switch to Light' : 'Switch to Dark';
  }
}

function updateSettingsAccount(user) {
  const guestInfo = document.getElementById('settings-guest-info');
  const userInfo = document.getElementById('settings-user-info');
  const signoutSection = document.getElementById('settings-signout-section');

  if (user) {
    if (guestInfo) guestInfo.style.display = 'none';
    if (userInfo) userInfo.style.display = '';
    if (signoutSection) signoutSection.style.display = '';

    const emailEl = document.getElementById('settings-email');
    const nameEl = document.getElementById('settings-display-name');
    const providerEl = document.getElementById('settings-provider');
    const createdEl = document.getElementById('settings-created');

    if (emailEl) emailEl.textContent = user.email || 'N/A';
    if (nameEl) nameEl.textContent = user.displayName || 'N/A';

    const providerData = user.providerData?.[0];
    let provider = 'Email';
    if (providerData) {
      if (providerData.providerId === 'google.com') provider = 'Google';
      else if (providerData.providerId === 'github.com') provider = 'GitHub';
    }
    if (providerEl) providerEl.textContent = provider;

    const created = user.metadata?.creationTime;
    if (createdEl) createdEl.textContent = created ? new Date(created).toLocaleDateString() : 'N/A';
  } else {
    if (guestInfo) guestInfo.style.display = '';
    if (userInfo) userInfo.style.display = 'none';
    if (signoutSection) signoutSection.style.display = 'none';
  }
}
