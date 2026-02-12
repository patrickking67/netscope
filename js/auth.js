/* ===== NetScope Auth Module ===== */

let auth = null;
let currentUser = null;

function initAuth() {
  if (typeof firebase === 'undefined') return;
  if (!firebase.apps.length) {
    try { firebase.initializeApp(firebaseConfig); } catch (e) { return; }
  }
  auth = firebase.auth();

  auth.onAuthStateChanged(user => {
    currentUser = user;
    updateAuthUI(user);
    if (user && typeof loadUserPreferences === 'function') {
      loadUserPreferences(user.uid);
    }
  });

  // Desktop login
  document.getElementById('btn-login')?.addEventListener('click', signIn);
  document.getElementById('btn-logout')?.addEventListener('click', signOut);
  document.getElementById('user-avatar-btn')?.addEventListener('click', toggleUserDropdown);
  document.getElementById('btn-my-results')?.addEventListener('click', () => { openResultsPanel(); closeUserDropdown(); });
  document.getElementById('btn-save-cloud')?.addEventListener('click', () => { if (typeof saveResults === 'function') saveResults(); });

  // Mobile login
  document.getElementById('mobile-btn-login')?.addEventListener('click', signIn);
  document.getElementById('mobile-btn-logout')?.addEventListener('click', signOut);
  document.getElementById('mobile-btn-results')?.addEventListener('click', openResultsPanel);

  // Close dropdown when clicking outside
  document.addEventListener('click', e => {
    const dropdown = document.getElementById('user-dropdown');
    const btn = document.getElementById('user-avatar-btn');
    if (dropdown && !dropdown.contains(e.target) && e.target !== btn && !btn?.contains(e.target)) {
      dropdown.classList.remove('open');
    }
  });
}

async function signIn() {
  if (!auth) { showToast('Firebase not configured yet'); return; }
  const provider = new firebase.auth.GoogleAuthProvider();
  try {
    await auth.signInWithPopup(provider);
    showToast('Signed in successfully');
    closeMobileMenu();
  } catch (err) {
    if (err.code === 'auth/popup-closed-by-user') return;
    if (err.code === 'auth/unauthorized-domain') {
      showToast('Domain not authorized in Firebase');
      return;
    }
    console.error('Auth error:', err);
    showToast('Sign in failed');
  }
}

async function signOut() {
  try {
    await auth.signOut();
    showToast('Signed out');
    closeUserDropdown();
    closeMobileMenu();
  } catch (err) {
    console.error('Sign out error:', err);
  }
}

function updateAuthUI(user) {
  const loginBtn = document.getElementById('btn-login');
  const userMenu = document.getElementById('user-menu');
  const userAvatar = document.getElementById('user-avatar');
  const userName = document.getElementById('user-name');
  const saveBtn = document.getElementById('btn-save-cloud');
  const mobileLoginBtn = document.getElementById('mobile-btn-login');
  const mobileUserInfo = document.getElementById('mobile-user-info');
  const mobileAvatar = document.getElementById('mobile-user-avatar');
  const mobileUserName = document.getElementById('mobile-user-name');

  if (user) {
    if (loginBtn) loginBtn.style.display = 'none';
    if (userMenu) userMenu.style.display = 'flex';
    if (userAvatar) { userAvatar.src = user.photoURL || ''; userAvatar.alt = user.displayName || 'User'; }
    if (userName) userName.textContent = user.displayName || user.email;
    if (saveBtn) saveBtn.style.display = 'flex';
    if (mobileLoginBtn) mobileLoginBtn.style.display = 'none';
    if (mobileUserInfo) mobileUserInfo.style.display = 'block';
    if (mobileAvatar) { mobileAvatar.src = user.photoURL || ''; }
    if (mobileUserName) mobileUserName.textContent = user.displayName || user.email;
  } else {
    if (loginBtn) loginBtn.style.display = '';
    if (userMenu) userMenu.style.display = 'none';
    if (saveBtn) saveBtn.style.display = 'none';
    if (mobileLoginBtn) mobileLoginBtn.style.display = '';
    if (mobileUserInfo) mobileUserInfo.style.display = 'none';
  }
}

function toggleUserDropdown() {
  document.getElementById('user-dropdown')?.classList.toggle('open');
}

function closeUserDropdown() {
  document.getElementById('user-dropdown')?.classList.remove('open');
}

function closeMobileMenu() {
  const menu = document.getElementById('mobile-menu');
  const hamburger = document.getElementById('hamburger');
  if (menu) menu.classList.remove('open');
  if (hamburger) { hamburger.classList.remove('open'); hamburger.setAttribute('aria-expanded', 'false'); }
  document.body.style.overflow = '';
}

async function openResultsPanel() {
  const panel = document.getElementById('results-panel');
  const list = document.getElementById('results-list');
  if (!panel) return;
  panel.classList.add('open');
  document.body.style.overflow = 'hidden';

  if (typeof loadSavedResults !== 'function') {
    list.innerHTML = '<p class="results-empty">Firestore not configured.</p>';
    return;
  }

  list.innerHTML = '<p class="results-empty">Loading...</p>';
  const results = await loadSavedResults();

  if (results.length === 0) {
    list.innerHTML = '<p class="results-empty">No saved results yet. Run some tests and click "Save to Cloud".</p>';
    return;
  }

  list.innerHTML = results.map(r => `
    <div class="result-history-card">
      <div class="result-history-header">
        <span class="result-history-date">${r.timestamp.toLocaleDateString()} ${r.timestamp.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})}</span>
        <button class="result-history-delete" data-id="${r.id}" title="Delete">&times;</button>
      </div>
      <div class="result-history-body">
        ${r.ip ? `<div class="result-history-item"><span class="result-history-label">IP</span><span>${esc(r.ip)}</span></div>` : ''}
        ${r.geo ? `<div class="result-history-item"><span class="result-history-label">Location</span><span>${esc(r.geo.city || '')}, ${esc(r.geo.country || '')}</span></div>` : ''}
        ${r.speed ? `<div class="result-history-item"><span class="result-history-label">Speed</span><span>${r.speed.download} Mbps down / ${r.speed.upload} Mbps up / ${r.speed.ping} ms</span></div>` : ''}
        ${r.scan ? `<div class="result-history-item"><span class="result-history-label">DNS Scan</span><span>${esc(r.scan.domain)} (${r.scan.checksCount} checks)</span></div>` : ''}
      </div>
    </div>
  `).join('');

  // Bind delete buttons
  list.querySelectorAll('.result-history-delete').forEach(btn => {
    btn.addEventListener('click', async () => {
      await deleteResult(btn.dataset.id);
      openResultsPanel(); // Refresh
    });
  });
}

function closeResultsPanel() {
  const panel = document.getElementById('results-panel');
  if (panel) panel.classList.remove('open');
  document.body.style.overflow = '';
}

// Init close button
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('results-panel-close')?.addEventListener('click', closeResultsPanel);
});
