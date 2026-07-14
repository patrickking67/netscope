(function registerNetScopeServiceWorker() {
  if (!("serviceWorker" in navigator)) return;
  const scriptUrl = document.currentScript?.src;
  if (!scriptUrl) return;

  window.addEventListener("load", () => {
    const workerUrl = new URL("../../sw.js", scriptUrl);
    const scopeUrl = new URL("../../", scriptUrl);
    navigator.serviceWorker.register(workerUrl, { scope: scopeUrl.pathname }).catch(() => {});
  });
})();
