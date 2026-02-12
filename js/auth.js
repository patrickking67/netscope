/* ===== NetScope Auth Module ===== */

let auth = null;
let currentUser = null;
let isGuest = false;

function initAuth() {
  if (typeof firebase === 'undefined') return;
  if (!firebase.apps.length) {
    try { firebase.initializeApp(firebaseConfig); } catch (e) { return; }
  }
  auth = firebase.auth();

  isGuest = localStorage.getItem('netscope-guest') === 'true';

  auth.onAuthStateChanged(user => {
    currentUser = user;

    if (user) {
      localStorage.removeItem('netscope-guest');
      localStorage.setItem('netscope-session', 'active');
      isGuest = false;
      updateAuthUI(user);
      if (typeof updateSettingsAccount === 'function') updateSettingsAccount(user);
      if (typeof showDashboard === 'function') showDashboard();
      if (typeof loadUserPreferences === 'function') loadUserPreferences(user.uid);
    } else if (isGuest) {
      updateAuthUI(null);
      if (typeof updateSettingsAccount === 'function') updateSettingsAccount(null);
      if (typeof showDashboard === 'function') showDashboard();
    } else {
      updateAuthUI(null);
      if (typeof updateSettingsAccount === 'function') updateSettingsAccount(null);
      if (typeof showAuthGate === 'function') showAuthGate();
    }
  });

  bindAuthGateEvents();

  // Desktop header login (guest upgrade)
  document.getElementById('btn-login')?.addEventListener('click', () => {
    isGuest = false;
    localStorage.removeItem('netscope-guest');
    if (typeof showAuthGate === 'function') showAuthGate();
  });
  document.getElementById('btn-logout')?.addEventListener('click', handleSignOut);
  document.getElementById('user-avatar-btn')?.addEventListener('click', toggleUserDropdown);
  document.getElementById('btn-my-results')?.addEventListener('click', () => { openResultsPanel(); closeUserDropdown(); });
  document.getElementById('btn-save-cloud')?.addEventListener('click', () => { if (typeof saveResults === 'function') saveResults(); });

  // Mobile
  document.getElementById('mobile-btn-login')?.addEventListener('click', () => {
    closeMobileMenu();
    isGuest = false;
    localStorage.removeItem('netscope-guest');
    if (typeof showAuthGate === 'function') showAuthGate();
  });
  document.getElementById('mobile-btn-logout')?.addEventListener('click', handleSignOut);
  document.getElementById('mobile-btn-results')?.addEventListener('click', openResultsPanel);

  // Close dropdown on outside click
  document.addEventListener('click', e => {
    const dropdown = document.getElementById('user-dropdown');
    const btn = document.getElementById('user-avatar-btn');
    if (dropdown && !dropdown.contains(e.target) && e.target !== btn && !btn?.contains(e.target)) {
      dropdown.classList.remove('open');
    }
  });
}

// ============================================================
// AUTH GATE EVENTS
// ============================================================

function bindAuthGateEvents() {
  // Guest skip
  document.getElementById('btn-guest-skip')?.addEventListener('click', () => {
    localStorage.setItem('netscope-guest', 'true');
    isGuest = true;
    if (typeof showDashboard === 'function') showDashboard();
  });

  // Tab switching
  document.querySelectorAll('[data-auth-tab]').forEach(tab => {
    tab.addEventListener('click', () => switchAuthTab(tab.dataset.authTab));
  });

  // Social auth
  document.getElementById('auth-google-btn')?.addEventListener('click', signInWithGoogle);
  document.getElementById('auth-github-btn')?.addEventListener('click', signInWithGitHub);

  // Form submissions
  document.getElementById('auth-form-signin')?.addEventListener('submit', handleSignIn);
  document.getElementById('auth-form-signup')?.addEventListener('submit', handleSignUp);
  document.getElementById('auth-form-forgot')?.addEventListener('submit', handleForgotPassword);

  // Forgot password / back
  document.getElementById('auth-forgot-link')?.addEventListener('click', showForgotView);
  document.getElementById('auth-back-btn')?.addEventListener('click', showMainView);

  // Password visibility toggles
  document.querySelectorAll('.auth-toggle-password').forEach(btn => {
    btn.addEventListener('click', () => togglePasswordVisibility(btn.dataset.target));
  });
}

// ============================================================
// AUTH TAB / VIEW MANAGEMENT
// ============================================================

function switchAuthTab(tab) {
  document.querySelectorAll('[data-auth-tab]').forEach(t => {
    t.classList.toggle('active', t.dataset.authTab === tab);
  });
  const signinForm = document.getElementById('auth-form-signin');
  const signupForm = document.getElementById('auth-form-signup');
  const forgotLink = document.getElementById('auth-forgot-link');
  if (signinForm) signinForm.style.display = tab === 'signin' ? '' : 'none';
  if (signupForm) signupForm.style.display = tab === 'signup' ? '' : 'none';
  if (forgotLink) forgotLink.style.display = tab === 'signin' ? '' : 'none';
  clearAuthErrors();
}

function showForgotView() {
  document.getElementById('auth-view-main').style.display = 'none';
  document.getElementById('auth-view-forgot').style.display = '';
  const email = document.getElementById('auth-email-signin')?.value;
  if (email) document.getElementById('auth-email-forgot').value = email;
  clearAuthErrors();
  const successEl = document.getElementById('auth-success-forgot');
  if (successEl) successEl.style.display = 'none';
}

function showMainView() {
  document.getElementById('auth-view-main').style.display = '';
  document.getElementById('auth-view-forgot').style.display = 'none';
  clearAuthErrors();
}

function clearAuthErrors() {
  ['auth-error-signin', 'auth-error-signup', 'auth-error-forgot'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = '';
  });
}

function clearAuthForms() {
  ['auth-form-signin', 'auth-form-signup', 'auth-form-forgot'].forEach(id => {
    const form = document.getElementById(id);
    if (form) form.reset();
  });
  const successEl = document.getElementById('auth-success-forgot');
  if (successEl) successEl.style.display = 'none';
}

function togglePasswordVisibility(inputId) {
  const input = document.getElementById(inputId);
  if (!input) return;
  input.type = input.type === 'password' ? 'text' : 'password';
}

// ============================================================
// AUTH HELPERS
// ============================================================

function setAuthLoading(formId, loading) {
  const form = document.getElementById(formId);
  if (!form) return;
  const btn = form.querySelector('.auth-submit-btn');
  const text = form.querySelector('.auth-submit-text');
  const spinner = form.querySelector('.auth-submit-spinner');
  if (btn) btn.disabled = loading;
  if (text) text.style.display = loading ? 'none' : '';
  if (spinner) spinner.style.display = loading ? 'inline-flex' : 'none';
  form.querySelectorAll('input').forEach(i => i.disabled = loading);
}

function showAuthError(elementId, message) {
  const el = document.getElementById(elementId);
  if (el) el.textContent = message;
}

function getFirebaseAuthErrorMessage(code) {
  const messages = {
    'auth/email-already-in-use': 'An account with this email already exists.',
    'auth/invalid-email': 'Please enter a valid email address.',
    'auth/user-disabled': 'This account has been disabled.',
    'auth/user-not-found': 'No account found with this email.',
    'auth/wrong-password': 'Incorrect password. Please try again.',
    'auth/invalid-credential': 'Invalid email or password.',
    'auth/too-many-requests': 'Too many attempts. Please try again later.',
    'auth/weak-password': 'Password must be at least 6 characters.',
    'auth/network-request-failed': 'Network error. Check your connection.',
    'auth/popup-closed-by-user': null,
    'auth/unauthorized-domain': 'This domain is not authorized in Firebase.',
    'auth/operation-not-allowed': 'This sign-in method is not enabled. Enable it in the Firebase Console.',
    'auth/account-exists-with-different-credential': 'An account already exists with this email using a different sign-in method.',
  };
  return messages[code] || 'An unexpected error occurred. Please try again.';
}

// ============================================================
// AUTH ACTIONS
// ============================================================

async function signInWithGoogle() {
  if (!auth) { showToast('Firebase not configured yet'); return; }
  const provider = new firebase.auth.GoogleAuthProvider();
  try {
    await auth.signInWithPopup(provider);
    showToast('Signed in successfully');
  } catch (err) {
    if (err.code === 'auth/popup-closed-by-user') return;
    const msg = getFirebaseAuthErrorMessage(err.code);
    if (msg) showAuthError('auth-error-signin', msg);
    console.error('Auth error:', err);
  }
}

async function signInWithGitHub() {
  if (!auth) { showToast('Firebase not configured yet'); return; }
  const provider = new firebase.auth.GithubAuthProvider();
  try {
    await auth.signInWithPopup(provider);
    showToast('Signed in successfully');
  } catch (err) {
    if (err.code === 'auth/popup-closed-by-user') return;
    if (err.code === 'auth/account-exists-with-different-credential') {
      showAuthError('auth-error-signin', 'An account already exists with this email using a different sign-in method.');
      return;
    }
    const msg = getFirebaseAuthErrorMessage(err.code);
    if (msg) showAuthError('auth-error-signin', msg);
    console.error('GitHub auth error:', err);
  }
}

async function handleSignIn(e) {
  e.preventDefault();
  clearAuthErrors();

  const email = document.getElementById('auth-email-signin')?.value.trim();
  const password = document.getElementById('auth-password-signin')?.value;

  if (!email || !password) {
    showAuthError('auth-error-signin', 'Please enter both email and password.');
    return;
  }

  setAuthLoading('auth-form-signin', true);
  try {
    await auth.signInWithEmailAndPassword(email, password);
    showToast('Signed in successfully');
  } catch (err) {
    const msg = getFirebaseAuthErrorMessage(err.code);
    if (msg) showAuthError('auth-error-signin', msg);
    console.error('Sign in error:', err);
  } finally {
    setAuthLoading('auth-form-signin', false);
  }
}

async function handleSignUp(e) {
  e.preventDefault();
  clearAuthErrors();

  const email = document.getElementById('auth-email-signup')?.value.trim();
  const password = document.getElementById('auth-password-signup')?.value;
  const confirm = document.getElementById('auth-password-confirm')?.value;

  if (!email || !password || !confirm) {
    showAuthError('auth-error-signup', 'Please fill in all fields.');
    return;
  }
  if (password !== confirm) {
    showAuthError('auth-error-signup', 'Passwords do not match.');
    return;
  }
  if (password.length < 6) {
    showAuthError('auth-error-signup', 'Password must be at least 6 characters.');
    return;
  }

  setAuthLoading('auth-form-signup', true);
  try {
    const result = await auth.createUserWithEmailAndPassword(email, password);
    try {
      await result.user.sendEmailVerification();
    } catch (verifyErr) {
      console.warn('Email verification send failed:', verifyErr);
    }
    showToast('Account created successfully');
  } catch (err) {
    const msg = getFirebaseAuthErrorMessage(err.code);
    if (msg) showAuthError('auth-error-signup', msg);
    console.error('Sign up error:', err);
  } finally {
    setAuthLoading('auth-form-signup', false);
  }
}

async function handleForgotPassword(e) {
  e.preventDefault();
  clearAuthErrors();
  const successEl = document.getElementById('auth-success-forgot');
  if (successEl) successEl.style.display = 'none';

  const email = document.getElementById('auth-email-forgot')?.value.trim();
  if (!email) {
    showAuthError('auth-error-forgot', 'Please enter your email address.');
    return;
  }

  setAuthLoading('auth-form-forgot', true);
  try {
    await auth.sendPasswordResetEmail(email);
    if (successEl) {
      successEl.textContent = 'Reset link sent! Check your inbox (and spam folder).';
      successEl.style.display = '';
    }
  } catch (err) {
    const msg = getFirebaseAuthErrorMessage(err.code);
    if (msg) showAuthError('auth-error-forgot', msg);
    console.error('Password reset error:', err);
  } finally {
    setAuthLoading('auth-form-forgot', false);
  }
}

async function handleSignOut() {
  try {
    await auth.signOut();
    localStorage.removeItem('netscope-guest');
    localStorage.removeItem('netscope-session');
    isGuest = false;
    showToast('Signed out');
    closeUserDropdown();
    closeMobileMenu();
  } catch (err) {
    console.error('Sign out error:', err);
  }
}

// ============================================================
// AUTH UI
// ============================================================

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
    if (saveBtn) saveBtn.style.display = 'flex';
    if (mobileLoginBtn) mobileLoginBtn.style.display = 'none';
    if (mobileUserInfo) mobileUserInfo.style.display = 'block';

    const displayName = user.displayName || user.email;
    if (userName) userName.textContent = displayName;
    if (mobileUserName) mobileUserName.textContent = displayName;

    if (user.photoURL) {
      setAvatarImage(userAvatar, user.photoURL, displayName);
      setAvatarImage(mobileAvatar, user.photoURL, displayName);
    } else {
      setDefaultAvatar(userAvatar, user.email, false);
      setDefaultAvatar(mobileAvatar, user.email, true);
    }

    updateVerificationBanner(user);
  } else {
    // Show login button when guest (in dashboard), hide otherwise (on auth gate)
    if (loginBtn) loginBtn.style.display = isGuest ? '' : 'none';
    if (userMenu) userMenu.style.display = 'none';
    if (saveBtn) saveBtn.style.display = 'none';
    if (mobileLoginBtn) mobileLoginBtn.style.display = isGuest ? '' : 'none';
    if (mobileUserInfo) mobileUserInfo.style.display = 'none';
    removeVerificationBanner();
  }
}

function setAvatarImage(el, url, alt) {
  if (!el) return;
  if (el.tagName !== 'IMG') {
    const img = document.createElement('img');
    img.className = el.classList.contains('user-avatar-default--sm') ? 'user-avatar-sm' : 'user-avatar';
    img.id = el.id;
    img.width = el.classList.contains('user-avatar-default--sm') ? 22 : 28;
    img.height = img.width;
    el.replaceWith(img);
    el = img;
  }
  el.src = url;
  el.alt = alt || 'User';
}

function setDefaultAvatar(el, email, isSmall) {
  if (!el) return;
  if (el.classList.contains('user-avatar-default')) return;
  const letter = (email || '?')[0].toUpperCase();
  const div = document.createElement('div');
  div.className = 'user-avatar-default' + (isSmall ? ' user-avatar-default--sm' : '');
  div.id = el.id;
  div.textContent = letter;
  el.replaceWith(div);
}

function updateVerificationBanner(user) {
  removeVerificationBanner();
  const isEmailProvider = user.providerData.some(p => p.providerId === 'password');
  if (isEmailProvider && !user.emailVerified) {
    const banner = document.createElement('div');
    banner.className = 'auth-verify-banner';
    banner.id = 'auth-verify-banner';
    banner.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg><span>Email not verified. <a id="auth-resend-verify">Resend verification email</a></span>';
    const dropdownHeader = document.querySelector('.user-dropdown-header');
    if (dropdownHeader) {
      dropdownHeader.after(banner);
      document.getElementById('auth-resend-verify')?.addEventListener('click', async (e) => {
        e.preventDefault();
        try {
          await user.sendEmailVerification();
          showToast('Verification email sent');
        } catch (err) {
          showToast('Could not send verification email');
          console.error('Resend verification error:', err);
        }
      });
    }
  }
}

function removeVerificationBanner() {
  document.getElementById('auth-verify-banner')?.remove();
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
  const backdrop = document.getElementById('drawer-backdrop');
  if (menu) menu.classList.remove('open');
  if (backdrop) backdrop.classList.remove('open');
  if (hamburger) { hamburger.classList.remove('open'); hamburger.setAttribute('aria-expanded', 'false'); }
  document.body.style.overflow = '';
}

// ============================================================
// RESULTS PANEL
// ============================================================

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

  list.querySelectorAll('.result-history-delete').forEach(btn => {
    btn.addEventListener('click', async () => {
      await deleteResult(btn.dataset.id);
      openResultsPanel();
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
