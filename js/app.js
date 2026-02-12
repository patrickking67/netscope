/* ===== NetScope - Network Security Toolkit ===== */

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
  document.querySelectorAll('.tab-bar-item').forEach(tab => {
    tab.addEventListener('click', () => switchTab(tab.dataset.tab));
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
    t.classList.toggle('active', t.dataset.tab === tabId);
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
      document.querySelectorAll('.breach-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      document.querySelectorAll('.breach-content').forEach(c => c.classList.add('hidden'));
      document.querySelector(`[data-tab-content="${tab.dataset.tab}"]`).classList.remove('hidden');
    });
  });
}

function initPasswordToggle() {
  const toggle = document.getElementById('toggle-password');
  const input = document.getElementById('password-input');
  toggle.addEventListener('click', () => {
    input.type = input.type === 'password' ? 'text' : 'password';
  });
}

function initEventListeners() {
  document.getElementById('btn-speed-test').addEventListener('click', runSpeedTest);
  document.getElementById('btn-email-check').addEventListener('click', checkEmailBreach);
  document.getElementById('btn-password-check').addEventListener('click', checkPasswordBreach);
  document.getElementById('btn-scan').addEventListener('click', runDNSScan);
  document.getElementById('password-input').addEventListener('keydown', e => { if (e.key === 'Enter') checkPasswordBreach(); });
  document.getElementById('email-input').addEventListener('keydown', e => { if (e.key === 'Enter') checkEmailBreach(); });
  document.getElementById('scan-input').addEventListener('keydown', e => { if (e.key === 'Enter') runDNSScan(); });
}

// ============================================================
// IP & LOCATION - robust fallback chain
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
      const r = await fetch(url);
      const d = await r.json();
      ip = d.ip;
      if (ip) break;
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
    { url: `https://ipapi.co/${ip}/json/`, parse: parseIpapiCo },
    { url: `https://ipwho.is/${ip}`, parse: parseIpwhois },
    { url: `https://freeipapi.com/api/json/${ip}`, parse: parseFreeipapi },
  ];
  for (const api of geoApis) {
    try {
      const r = await fetch(api.url);
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

function parseIpapiCo(d) {
  if (d.error) return null;
  return {
    ip: d.ip, isp: d.org || 'N/A', org: d.org || 'N/A',
    asn: d.asn || 'N/A', type: d.version || 'N/A',
    proxy: false, hosting: false,
    country: d.country_name, countryCode: d.country_code,
    region: d.region, city: d.city, postal: d.postal,
    lat: d.latitude, lng: d.longitude,
    timezone: d.timezone, flag: d.country_code,
  };
}

function parseIpwhois(d) {
  if (!d.success) return null;
  return {
    ip: d.ip, isp: d.connection?.isp || 'N/A', org: d.connection?.org || 'N/A',
    asn: d.connection?.asn ? `AS${d.connection.asn}` : 'N/A', type: d.type || 'N/A',
    proxy: d.security?.proxy || false, hosting: d.security?.hosting || false,
    country: d.country, countryCode: d.country_code,
    region: d.region, city: d.city, postal: d.postal,
    lat: d.latitude, lng: d.longitude,
    timezone: d.timezone?.id || 'N/A', flag: d.country_code,
  };
}

function parseFreeipapi(d) {
  return {
    ip: d.ipAddress, isp: d.isp || 'N/A', org: d.isp || 'N/A',
    asn: 'N/A', type: d.ipVersion ? `IPv${d.ipVersion}` : 'N/A',
    proxy: d.isProxy || false, hosting: false,
    country: d.countryName, countryCode: d.countryCode,
    region: d.regionName, city: d.cityName, postal: d.zipCode,
    lat: d.latitude, lng: d.longitude,
    timezone: d.timeZone, flag: d.countryCode,
  };
}

function renderGeo(g) {
  setVal('info-isp', g.isp);
  setVal('info-org', g.org);
  setVal('info-asn', g.asn);
  setVal('info-type', g.type);
  setVal('info-proxy', g.proxy ? 'Yes - Detected' : 'No');
  setVal('info-hosting', g.hosting ? 'Yes' : 'No');
  const flag = g.countryCode ? countryFlag(g.countryCode) + ' ' : '';
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

function countryFlag(code) {
  if (!code || code.length !== 2) return '';
  return String.fromCodePoint(...[...code.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
}

// ============================================================
// SPEED TEST - Multi-connection, time-based (Ookla-style)
// ============================================================
let speedRunning = false;

async function runSpeedTest() {
  if (speedRunning) return;
  speedRunning = true;
  const btn = document.getElementById('btn-speed-test');
  const phase = document.getElementById('speed-phase');
  const ring = document.getElementById('gauge-ring');
  btn.disabled = true;
  btn.textContent = 'Testing...';
  ring.classList.add('active');
  phase.classList.add('active');
  resetGauge();

  try {
    // LATENCY + JITTER
    phase.textContent = 'Testing latency...';
    const latency = await testLatency();
    state.speed.ping = latency.ping;
    state.speed.jitter = latency.jitter;
    animateNumber(document.getElementById('speed-ping'), latency.ping, 0);
    animateNumber(document.getElementById('speed-jitter'), latency.jitter, 1);

    // DOWNLOAD (multi-connection, ~12s)
    phase.textContent = 'Testing download...';
    const dl = await testMultiDownload();
    state.speed.download = dl;
    animateNumber(document.getElementById('speed-download'), dl, 1);
    setGauge(dl);
    animateNumber(document.getElementById('gauge-number'), dl, 1);

    // UPLOAD (multi-connection, ~12s)
    phase.textContent = 'Testing upload...';
    const ul = await testMultiUpload();
    state.speed.upload = ul;
    animateNumber(document.getElementById('speed-upload'), ul, 1);

    phase.textContent = 'Test complete';
  } catch (err) {
    console.error('Speed test error:', err);
    phase.textContent = 'Test finished with partial results';
  } finally {
    speedRunning = false;
    btn.disabled = false;
    btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><polygon points="5 3 19 12 5 21 5 3"/></svg> Run Again';
    ring.classList.remove('active');
    phase.classList.remove('active');
  }
}

async function testLatency() {
  const results = [];
  // Warmup ping
  try { await fetch(`https://speed.cloudflare.com/__down?measId=warmup&bytes=0`, { cache: 'no-store' }); } catch {}

  for (let i = 0; i < 20; i++) {
    const start = performance.now();
    try {
      await fetch(`https://speed.cloudflare.com/__down?measId=${Date.now()}-p${i}&bytes=0`, { cache: 'no-store' });
    } catch {
      try {
        await fetch(`https://www.google.com/generate_204?_=${Date.now()}-${i}`, { mode: 'no-cors', cache: 'no-store' });
      } catch { continue; }
    }
    results.push(performance.now() - start);
  }

  if (results.length === 0) return { ping: 0, jitter: 0 };

  results.sort((a, b) => a - b);
  const trim = Math.max(1, Math.floor(results.length * 0.1));
  const trimmed = results.slice(trim, -trim);
  const ping = trimmed[Math.floor(trimmed.length / 2)];

  // Jitter = mean absolute difference between consecutive pings
  let jitterSum = 0;
  for (let i = 1; i < trimmed.length; i++) {
    jitterSum += Math.abs(trimmed[i] - trimmed[i - 1]);
  }
  const jitter = trimmed.length > 1 ? jitterSum / (trimmed.length - 1) : 0;

  return { ping, jitter };
}

async function testCfAvailable() {
  try {
    const r = await fetch(`https://speed.cloudflare.com/__down?measId=${Date.now()}&bytes=1000`, { cache: 'no-store' });
    return r.ok;
  } catch { return false; }
}

async function testMultiDownload() {
  const cfWorks = await testCfAvailable();
  if (!cfWorks) return await fallbackDownload();

  const CONNECTIONS = 4;
  const TOTAL_MS = 12000;
  const WARMUP_MS = 2000;
  const transfers = [];
  const testStart = performance.now();

  async function worker(id) {
    let size = 100000;
    while (performance.now() - testStart < TOTAL_MS) {
      const fetchStart = performance.now();
      try {
        const r = await fetch(`https://speed.cloudflare.com/__down?measId=${Date.now()}-d${id}&bytes=${size}`, { cache: 'no-store' });
        const buf = await r.arrayBuffer();
        const fetchEnd = performance.now();
        const fetchDuration = fetchEnd - fetchStart;
        transfers.push({ bytes: buf.byteLength, endTime: fetchEnd });

        // Adaptive payload sizing
        if (fetchDuration < 500) size = Math.min(size * 6, 25000000);
        else if (fetchDuration < 1500) size = Math.min(size * 3, 25000000);
        else if (fetchDuration < 3000) size = Math.min(Math.round(size * 1.5), 25000000);

        // Update gauge during measurement window
        if (fetchEnd - testStart > WARMUP_MS) {
          const measured = transfers.filter(t => t.endTime > testStart + WARMUP_MS);
          const measuredBytes = measured.reduce((s, t) => s + t.bytes, 0);
          const elapsed = (fetchEnd - testStart - WARMUP_MS) / 1000;
          if (elapsed > 0) {
            const mbps = (measuredBytes * 8) / elapsed / 1e6;
            setGauge(mbps);
            animateNumber(document.getElementById('gauge-number'), mbps, 1);
          }
        }
      } catch { break; }
    }
  }

  const workers = [];
  for (let i = 0; i < CONNECTIONS; i++) workers.push(worker(i));
  await Promise.allSettled(workers);

  const warmupEnd = testStart + WARMUP_MS;
  const measured = transfers.filter(t => t.endTime > warmupEnd);
  const measuredBytes = measured.reduce((s, t) => s + t.bytes, 0);
  const elapsed = measured.length > 0 ? (Math.max(...measured.map(t => t.endTime)) - warmupEnd) / 1000 : 0;
  const mbps = elapsed > 0 ? (measuredBytes * 8) / elapsed / 1e6 : 0;

  setGauge(mbps);
  animateNumber(document.getElementById('gauge-number'), mbps, 1);
  return mbps;
}

async function fallbackDownload() {
  const urls = [
    { url: 'https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js', size: 71000 },
    { url: 'https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js', size: 640000 },
  ];
  let bestSpeed = 0;
  for (const { url, size } of urls) {
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const start = performance.now();
        const r = await fetch(`${url}?_=${Date.now()}-${attempt}`, { cache: 'no-store' });
        const buf = await r.arrayBuffer();
        const secs = (performance.now() - start) / 1000;
        const mbps = (buf.byteLength * 8) / secs / 1e6;
        if (mbps > bestSpeed) bestSpeed = mbps;
        setGauge(mbps);
        animateNumber(document.getElementById('gauge-number'), mbps, 1);
      } catch { break; }
    }
  }
  return bestSpeed;
}

async function testMultiUpload() {
  const CONNECTIONS = 4;
  const TOTAL_MS = 12000;
  const WARMUP_MS = 2000;
  const transfers = [];
  const testStart = performance.now();

  async function worker(id) {
    let size = 100000;
    while (performance.now() - testStart < TOTAL_MS) {
      const fetchStart = performance.now();
      try {
        const data = new Blob([new ArrayBuffer(size)]);
        const r = await fetch('https://speed.cloudflare.com/__up', { method: 'POST', body: data, cache: 'no-store' });
        if (!r.ok) break;
        const fetchEnd = performance.now();
        const fetchDuration = fetchEnd - fetchStart;
        transfers.push({ bytes: size, endTime: fetchEnd });

        if (fetchDuration < 500) size = Math.min(size * 6, 10000000);
        else if (fetchDuration < 1500) size = Math.min(size * 3, 10000000);
        else if (fetchDuration < 3000) size = Math.min(Math.round(size * 1.5), 10000000);
      } catch { break; }
    }
  }

  const workers = [];
  for (let i = 0; i < CONNECTIONS; i++) workers.push(worker(i));
  await Promise.allSettled(workers);

  const warmupEnd = testStart + WARMUP_MS;
  const measured = transfers.filter(t => t.endTime > warmupEnd);
  const measuredBytes = measured.reduce((s, t) => s + t.bytes, 0);
  const elapsed = measured.length > 0 ? (Math.max(...measured.map(t => t.endTime)) - warmupEnd) / 1000 : 0;
  const mbps = elapsed > 0 ? (measuredBytes * 8) / elapsed / 1e6 : 0;

  return mbps;
}

function resetGauge() {
  document.getElementById('gauge-circle').style.strokeDashoffset = '364.42';
  document.getElementById('gauge-number').textContent = '0';
  document.getElementById('speed-ping').textContent = '--';
  document.getElementById('speed-jitter').textContent = '--';
  document.getElementById('speed-download').textContent = '--';
  document.getElementById('speed-upload').textContent = '--';
}

function setGauge(mbps) {
  const circumference = 2 * Math.PI * 58; // 364.42
  const maxSpeed = 300;
  const pct = Math.min(mbps / maxSpeed, 1);
  document.getElementById('gauge-circle').style.strokeDashoffset = circumference * (1 - pct);
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
// BREACH CHECK - EMAIL (XposedOrNot + HIBP link fallback)
// ============================================================
async function checkEmailBreach() {
  const email = document.getElementById('email-input').value.trim();
  if (!email || !email.includes('@')) {
    showToast('Enter a valid email address');
    return;
  }
  const resultEl = document.getElementById('email-result');
  const btn = document.getElementById('btn-email-check');
  btn.disabled = true;
  resultEl.innerHTML = '<div style="color:var(--text-muted);text-align:center;padding:20px;">Checking breaches...</div>';

  let found = false;
  let breaches = [];

  // Try XposedOrNot API (free, no key)
  try {
    const r = await fetch(`https://api.xposedornot.com/v1/check-email/${encodeURIComponent(email)}`);
    if (r.ok) {
      const data = await r.json();
      if (data.breaches && data.breaches.length > 0) {
        found = true;
        breaches = data.breaches.map(b => typeof b === 'string' ? { name: b } : b);
      }
    } else if (r.status === 404) {
      // Not found = safe
    }
  } catch {
    // API failed - try alternate
    try {
      const r = await fetch(`https://api.xposedornot.com/v1/breach-analytics?email=${encodeURIComponent(email)}`);
      if (r.ok) {
        const data = await r.json();
        const exposedBreaches = data.ExposedBreaches?.breaches_details;
        if (exposedBreaches && exposedBreaches.length > 0) {
          found = true;
          breaches = exposedBreaches.map(b => ({ name: b.breach, domain: b.domain }));
        }
      }
    } catch {}
  }

  if (found && breaches.length > 0) {
    resultEl.innerHTML = `
      <div class="result-card result-card--danger">
        <div class="result-icon">&#x26A0;&#xFE0F;</div>
        <div class="result-title">Found in ${breaches.length} breach${breaches.length > 1 ? 'es' : ''}</div>
        <div class="result-sub">This email has appeared in known data breaches.</div>
      </div>
      <div class="breach-list">
        ${breaches.map(b => `<div class="breach-item"><div class="breach-item-name">${esc(b.name || b.breach || 'Unknown')}</div>${b.domain ? `<div class="breach-item-domain">${esc(b.domain)}</div>` : ''}</div>`).join('')}
      </div>
      <a href="https://haveibeenpwned.com/account/${encodeURIComponent(email)}" target="_blank" rel="noopener" class="hibp-link">View full details on Have I Been Pwned &rarr;</a>
    `;
  } else if (found === false) {
    resultEl.innerHTML = `
      <div class="result-card result-card--safe">
        <div class="result-icon">&#x2705;</div>
        <div class="result-title">No breaches found</div>
        <div class="result-sub">This email wasn't found in our breach database check.</div>
      </div>
      <a href="https://haveibeenpwned.com/account/${encodeURIComponent(email)}" target="_blank" rel="noopener" class="hibp-link">Double-check on Have I Been Pwned &rarr;</a>
    `;
  }

  state.breach.email = { email, found, count: breaches.length };
  btn.disabled = false;
}

// ============================================================
// BREACH CHECK - PASSWORD (HIBP k-anonymity)
// ============================================================
async function checkPasswordBreach() {
  const password = document.getElementById('password-input').value;
  if (!password) { showToast('Enter a password to check'); return; }

  const resultEl = document.getElementById('password-result');
  const btn = document.getElementById('btn-password-check');
  btn.disabled = true;
  resultEl.innerHTML = '<div style="color:var(--text-muted);text-align:center;padding:20px;">Checking...</div>';

  try {
    const encoder = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest('SHA-1', encoder.encode(password));
    const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    const prefix = hashHex.substring(0, 5);
    const suffix = hashHex.substring(5);

    const r = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    const text = await r.text();
    let count = 0;
    for (const line of text.split('\n')) {
      const [h, c] = line.split(':');
      if (h.trim() === suffix) { count = parseInt(c.trim(), 10); break; }
    }

    if (count === 0) {
      resultEl.innerHTML = `
        <div class="result-card result-card--safe">
          <div class="result-icon">&#x2705;</div>
          <div class="result-title">Not found in any breaches</div>
          <div class="result-sub">This password hasn't appeared in known data breaches. Still use unique passwords everywhere.</div>
        </div>`;
    } else {
      resultEl.innerHTML = `
        <div class="result-card result-card--danger">
          <div class="result-icon">&#x26A0;&#xFE0F;</div>
          <div class="result-title">Found ${count.toLocaleString()} times</div>
          <div class="result-sub">This password has been seen in data breaches. Change it immediately and never reuse it.</div>
        </div>`;
    }
    state.breach.password = { count };
  } catch (err) {
    console.error('Password check error:', err);
    resultEl.innerHTML = '<div style="color:var(--accent-red);text-align:center;padding:20px;">Error checking password. Try again.</div>';
  }
  btn.disabled = false;
}

// ============================================================
// DNS & SECURITY SCAN
// ============================================================
async function runDNSScan() {
  const raw = document.getElementById('scan-input').value.trim();
  if (!raw) { showToast('Enter a domain or email'); return; }

  const btn = document.getElementById('btn-scan');
  const resultsEl = document.getElementById('scan-results');
  btn.disabled = true;
  btn.textContent = 'Scanning...';
  resultsEl.innerHTML = '<div style="color:var(--text-muted);text-align:center;padding:24px;">Running scan...</div>';

  // Extract domain from email or raw domain
  const domain = raw.includes('@') ? raw.split('@')[1] : raw.replace(/^https?:\/\//, '').split('/')[0];
  const isEmail = raw.includes('@');

  let html = '';

  // 1. DNS Records
  html += '<div class="scan-section"><div class="scan-section-title">DNS Records</div>';
  const recordTypes = ['A', 'AAAA', 'MX', 'NS'];
  for (const type of recordTypes) {
    try {
      const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`);
      const data = await r.json();
      if (data.Answer && data.Answer.length > 0) {
        for (const rec of data.Answer) {
          html += `<div class="dns-record">
            <span class="dns-record-type">${dnsTypeName(rec.type)}</span>
            <span class="dns-record-value">${esc(rec.data)}</span>
            <span class="dns-record-ttl">TTL ${rec.TTL}s</span>
          </div>`;
        }
      }
    } catch {}
  }
  html += '</div>';

  // 2. Email Security (SPF, DMARC, DKIM)
  html += '<div class="scan-section"><div class="scan-section-title">Email Security</div>';
  const checks = [];

  // SPF
  try {
    const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=TXT`);
    const data = await r.json();
    const spfRecord = data.Answer?.find(a => a.data && a.data.includes('v=spf1'));
    if (spfRecord) {
      checks.push({ icon: 'pass', name: 'SPF Record', detail: 'Sender Policy Framework is configured', value: spfRecord.data });
    } else {
      checks.push({ icon: 'fail', name: 'SPF Record', detail: 'No SPF record found - emails can be spoofed' });
    }
  } catch {
    checks.push({ icon: 'warn', name: 'SPF Record', detail: 'Could not check SPF' });
  }

  // DMARC
  try {
    const r = await fetch(`https://dns.google/resolve?name=_dmarc.${encodeURIComponent(domain)}&type=TXT`);
    const data = await r.json();
    const dmarcRecord = data.Answer?.find(a => a.data && a.data.includes('v=DMARC1'));
    if (dmarcRecord) {
      const policy = dmarcRecord.data.match(/p=(\w+)/)?.[1] || 'unknown';
      checks.push({
        icon: policy === 'reject' ? 'pass' : policy === 'quarantine' ? 'pass' : 'warn',
        name: 'DMARC Policy',
        detail: `Policy: ${policy}${policy === 'none' ? ' (monitoring only - not enforcing)' : ''}`,
        value: dmarcRecord.data,
      });
    } else {
      checks.push({ icon: 'fail', name: 'DMARC Policy', detail: 'No DMARC record found - domain is vulnerable to email spoofing' });
    }
  } catch {
    checks.push({ icon: 'warn', name: 'DMARC Policy', detail: 'Could not check DMARC' });
  }

  // DKIM (check common selectors)
  const dkimSelectors = ['default', 'google', 'selector1', 'selector2', 'k1', 's1', 'dkim'];
  let dkimFound = false;
  for (const sel of dkimSelectors) {
    try {
      const r = await fetch(`https://dns.google/resolve?name=${sel}._domainkey.${encodeURIComponent(domain)}&type=TXT`);
      const data = await r.json();
      if (data.Answer && data.Answer.length > 0 && data.Answer.some(a => a.data?.includes('v=DKIM1') || a.data?.includes('p='))) {
        dkimFound = true;
        checks.push({ icon: 'pass', name: 'DKIM', detail: `DKIM key found at selector: ${sel}` });
        break;
      }
    } catch {}
  }
  if (!dkimFound) {
    checks.push({ icon: 'info', name: 'DKIM', detail: 'No DKIM keys found at common selectors (may use custom selectors)' });
  }

  // DNSSEC
  try {
    const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A&do=1`);
    const data = await r.json();
    checks.push({
      icon: data.AD ? 'pass' : 'warn',
      name: 'DNSSEC',
      detail: data.AD ? 'DNSSEC signatures are validated for this domain' : 'DNSSEC is not enabled or not validated',
    });
  } catch {
    checks.push({ icon: 'warn', name: 'DNSSEC', detail: 'Could not verify DNSSEC' });
  }

  // MX check
  try {
    const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=MX`);
    const data = await r.json();
    if (data.Answer && data.Answer.length > 0) {
      const mxServers = data.Answer.map(a => a.data).join(', ');
      checks.push({ icon: 'info', name: 'Mail Servers', detail: `${data.Answer.length} MX record(s) found`, value: mxServers });
    } else {
      checks.push({ icon: 'warn', name: 'Mail Servers', detail: 'No MX records found - domain may not receive email' });
    }
  } catch {}

  // WebRTC leak check
  try {
    const ips = await checkWebRTC();
    checks.push({
      icon: ips.length === 0 ? 'pass' : 'warn',
      name: 'WebRTC Leak',
      detail: ips.length === 0 ? 'No local IPs leaked via WebRTC' : `Local IPs detected: ${ips.join(', ')}`,
    });
  } catch {}

  // HTTPS
  checks.push({
    icon: location.protocol === 'https:' ? 'pass' : 'fail',
    name: 'Your Connection',
    detail: location.protocol === 'https:' ? 'You are browsing this page over HTTPS' : 'Not using HTTPS',
  });

  state.scan = { domain, checks };

  for (const c of checks) {
    html += `<div class="security-check">
      <div class="check-icon check-icon--${c.icon}">${c.icon === 'pass' ? '&#x2713;' : c.icon === 'fail' ? '&#x2717;' : c.icon === 'warn' ? '!' : 'i'}</div>
      <div>
        <div class="check-name">${esc(c.name)}</div>
        <div class="check-detail">${esc(c.detail)}</div>
        ${c.value ? `<div class="check-value">${esc(c.value)}</div>` : ''}
      </div>
    </div>`;
  }
  html += '</div>';

  resultsEl.innerHTML = html;
  btn.disabled = false;
  btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg> Scan';
}

async function checkWebRTC() {
  return new Promise(resolve => {
    const ips = new Set();
    try {
      const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
      pc.createDataChannel('');
      pc.createOffer().then(o => pc.setLocalDescription(o));
      pc.onicecandidate = e => {
        if (!e.candidate) { pc.close(); resolve([...ips]); return; }
        const parts = e.candidate.candidate.split(' ');
        if (parts.length > 4) {
          const ip = parts[4];
          if (ip && !ip.endsWith('.local') && !ip.includes(':')) ips.add(ip);
        }
      };
      setTimeout(() => { pc.close(); resolve([...ips]); }, 3000);
    } catch { resolve([]); }
  });
}

function dnsTypeName(t) {
  const m = { 1:'A', 2:'NS', 5:'CNAME', 6:'SOA', 15:'MX', 16:'TXT', 28:'AAAA', 33:'SRV', 257:'CAA' };
  return m[t] || `TYPE${t}`;
}

// ============================================================
// EXPORT
// ============================================================
function buildText() {
  const L = ['=== NetScope Results ===', `Generated: ${new Date().toLocaleString()}`, ''];
  if (state.ip) {
    L.push('--- IP & Location ---');
    L.push(`IP: ${state.ip}`);
    if (state.geo) {
      const g = state.geo;
      L.push(`ISP: ${g.isp}`, `Org: ${g.org}`, `ASN: ${g.asn}`, `Type: ${g.type}`);
      L.push(`Country: ${g.country}`, `Region: ${g.region}`, `City: ${g.city}`);
      L.push(`Coords: ${g.lat}, ${g.lng}`, `Timezone: ${g.timezone}`);
    }
    L.push('');
  }
  if (state.speed.ping !== null) {
    L.push('--- Speed Test ---');
    L.push(`Ping: ${state.speed.ping?.toFixed(0)} ms`);
    L.push(`Jitter: ${state.speed.jitter?.toFixed(1)} ms`);
    L.push(`Download: ${state.speed.download?.toFixed(1)} Mbps`);
    L.push(`Upload: ${state.speed.upload?.toFixed(1)} Mbps`);
    L.push('');
  }
  if (state.scan) {
    L.push(`--- DNS & Security: ${state.scan.domain} ---`);
    state.scan.checks.forEach(c => {
      const tag = { pass: '[PASS]', fail: '[FAIL]', warn: '[WARN]', info: '[INFO]' }[c.icon] || '[?]';
      L.push(`${tag} ${c.name}: ${c.detail}`);
    });
    L.push('');
  }
  L.push('Generated by NetScope');
  return L.join('\n');
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

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

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
const CHARSETS = {
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lower: 'abcdefghijklmnopqrstuvwxyz',
  numbers: '0123456789',
  symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?',
};

function initPasswordGenerator() {
  const slider = document.getElementById('pwgen-length');
  const lengthVal = document.getElementById('pwgen-length-val');
  slider.addEventListener('input', () => { lengthVal.textContent = slider.value; });

  document.getElementById('btn-generate').addEventListener('click', generatePassword);
  document.getElementById('pwgen-copy').addEventListener('click', copyPassword);
}

function generatePassword() {
  const length = parseInt(document.getElementById('pwgen-length').value, 10);
  let pool = '';
  if (document.getElementById('pwgen-upper').checked) pool += CHARSETS.upper;
  if (document.getElementById('pwgen-lower').checked) pool += CHARSETS.lower;
  if (document.getElementById('pwgen-numbers').checked) pool += CHARSETS.numbers;
  if (document.getElementById('pwgen-symbols').checked) pool += CHARSETS.symbols;

  if (!pool) {
    showToast('Select at least one character set');
    return;
  }

  const arr = new Uint32Array(length);
  crypto.getRandomValues(arr);
  let password = '';
  for (let i = 0; i < length; i++) {
    password += pool[arr[i] % pool.length];
  }

  document.getElementById('pwgen-password').textContent = password;
  updateStrength(password);
}

function updateStrength(password) {
  const bar = document.getElementById('pwgen-strength-bar');
  const label = document.getElementById('pwgen-strength-label');

  // Calculate entropy-based strength
  let poolSize = 0;
  if (/[a-z]/.test(password)) poolSize += 26;
  if (/[A-Z]/.test(password)) poolSize += 26;
  if (/[0-9]/.test(password)) poolSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) poolSize += 32;

  const entropy = password.length * Math.log2(poolSize || 1);
  let pct, color, text;

  if (entropy < 40) {
    pct = 20; color = 'var(--accent-red)'; text = 'Weak';
  } else if (entropy < 60) {
    pct = 40; color = 'var(--accent-orange)'; text = 'Fair';
  } else if (entropy < 80) {
    pct = 60; color = 'var(--accent-blue)'; text = 'Good';
  } else if (entropy < 100) {
    pct = 80; color = 'var(--accent-cyan)'; text = 'Strong';
  } else {
    pct = 100; color = 'var(--accent-green)'; text = 'Very Strong';
  }

  bar.style.width = pct + '%';
  bar.style.background = color;
  label.textContent = `${text} (${Math.round(entropy)} bits of entropy)`;
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
  ['fs-ip', 'fs-speed', 'fs-password', 'fs-dns'].forEach(id => setFsStep(id, '', 'Waiting'));
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
    if (!speedRunning) await runSpeedTest();
    setFsStep('fs-speed', 'done', 'Complete');
    setFsProgress(60);

    // 3. Password Generation
    if (fullScanCancelled) return;
    setFsStep('fs-password', 'running', 'Generating...');
    if (subtitle) subtitle.textContent = 'Generating secure password...';
    generatePassword();
    await new Promise(r => setTimeout(r, 500));
    setFsStep('fs-password', 'done', 'Complete');
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
