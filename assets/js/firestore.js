/* ===== NetScope Firestore Module ===== */

let db = null;

function initFirestore() {
  if (typeof firebase === 'undefined' || !firebase.apps.length) return;
  db = firebase.firestore();
}

async function saveResults() {
  if (!currentUser) { showToast('Sign in to save results'); return; }
  if (!db) { showToast('Database not available'); return; }

  const resultData = {
    timestamp: firebase.firestore.FieldValue.serverTimestamp(),
    type: 'full-scan',
    ip: state.ip || null,
    geo: state.geo ? {
      country: state.geo.country || null,
      region: state.geo.region || null,
      city: state.geo.city || null,
      isp: state.geo.isp || null,
      lat: state.geo.lat || null,
      lng: state.geo.lng || null,
    } : null,
    speed: state.speed.ping !== null ? {
      ping: Math.round(state.speed.ping),
      download: Number(state.speed.download?.toFixed(1)),
      upload: Number(state.speed.upload?.toFixed(1)),
    } : null,
    breach: state.breach.email ? {
      email: state.breach.email.email,
      found: state.breach.email.found,
      count: state.breach.email.count,
    } : null,
    scan: state.scan ? {
      domain: state.scan.domain,
      checksCount: state.scan.checks.length,
      checks: state.scan.checks.map(c => ({
        name: c.name,
        status: c.icon,
        detail: c.detail,
      })),
    } : null,
  };

  try {
    await db.collection('users').doc(currentUser.uid)
      .collection('results').add(resultData);
    showToast('Results saved to cloud');
    document.getElementById('export-panel')?.classList.remove('open');
  } catch (err) {
    console.error('Save error:', err);
    showToast('Could not save results');
  }
}

async function loadSavedResults() {
  if (!currentUser || !db) return [];
  try {
    const snapshot = await db.collection('users').doc(currentUser.uid)
      .collection('results')
      .orderBy('timestamp', 'desc')
      .limit(50)
      .get();
    return snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
      timestamp: doc.data().timestamp?.toDate() || new Date(),
    }));
  } catch (err) {
    console.error('Load error:', err);
    return [];
  }
}

async function deleteResult(resultId) {
  if (!currentUser || !db) return;
  try {
    await db.collection('users').doc(currentUser.uid)
      .collection('results').doc(resultId).delete();
    showToast('Result deleted');
  } catch (err) {
    console.error('Delete error:', err);
    showToast('Could not delete');
  }
}

async function saveUserPreferences(prefs) {
  if (!currentUser || !db) return;
  try {
    await db.collection('users').doc(currentUser.uid).set(
      { preferences: prefs },
      { merge: true }
    );
  } catch (err) {
    console.error('Prefs save error:', err);
  }
}

async function loadUserPreferences(uid) {
  if (!db) return;
  try {
    const doc = await db.collection('users').doc(uid).get();
    if (doc.exists) {
      const prefs = doc.data().preferences;
      if (prefs?.theme) {
        applyTheme(prefs.theme);
        localStorage.setItem('netscope-theme', prefs.theme);
      }
    }
  } catch (err) {
    console.error('Prefs load error:', err);
  }
}
