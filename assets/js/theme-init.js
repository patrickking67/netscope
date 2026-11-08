/* Runs synchronously in <head> so the saved theme applies before first paint.
 * Kept as an external file so the Content-Security-Policy can forbid inline scripts.
 * On the landing page, data-redirect-target sends returning users straight to the app.
 */
(function () {
  var script = document.currentScript;
  try {
    if (localStorage.getItem('netscope-theme') === 'light') {
      document.documentElement.setAttribute('data-theme', 'light');
    }
    var target = script && script.getAttribute('data-redirect-target');
    if (target && (localStorage.getItem('netscope-session') === 'active' || localStorage.getItem('netscope-guest') === 'true')) {
      window.location.replace(target);
    }
  } catch (e) {
    // Storage can be blocked (private mode, strict settings). Fall back to defaults.
  }
})();
