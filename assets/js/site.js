/* Shared page chrome for the landing and about pages: theme toggle, mobile
 * drawer, scroll reveal and the loading screen. Moved out of inline <script>
 * blocks so the Content-Security-Policy can forbid inline scripts.
 */
document.addEventListener('DOMContentLoaded', () => {
  // Theme toggle
  document.getElementById('theme-toggle')?.addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme') || 'dark';
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    try { localStorage.setItem('netscope-theme', next); } catch (e) { /* storage blocked */ }
    const label = document.getElementById('mobile-theme-label');
    if (label) label.textContent = next === 'dark' ? 'Light Mode' : 'Dark Mode';
  });
  document.getElementById('mobile-theme-toggle')?.addEventListener('click', () => {
    document.getElementById('theme-toggle')?.click();
  });

  // Mobile drawer
  const hamburger = document.getElementById('hamburger');
  const drawer = document.getElementById('mobile-menu');
  const backdrop = document.getElementById('drawer-backdrop');
  const closeBtn = document.getElementById('drawer-close');
  if (hamburger && drawer) {
    const handleEsc = (e) => { if (e.key === 'Escape') closeDrawer(); };
    const openDrawer = () => {
      drawer.classList.add('open');
      backdrop?.classList.add('open');
      hamburger.classList.add('open');
      hamburger.setAttribute('aria-expanded', 'true');
      document.body.style.overflow = 'hidden';
      closeBtn?.focus();
      document.addEventListener('keydown', handleEsc);
    };
    const closeDrawer = () => {
      drawer.classList.remove('open');
      backdrop?.classList.remove('open');
      hamburger.classList.remove('open');
      hamburger.setAttribute('aria-expanded', 'false');
      document.body.style.overflow = '';
      document.removeEventListener('keydown', handleEsc);
    };
    hamburger.addEventListener('click', () => {
      drawer.classList.contains('open') ? closeDrawer() : openDrawer();
    });
    backdrop?.addEventListener('click', closeDrawer);
    closeBtn?.addEventListener('click', closeDrawer);
    drawer.querySelectorAll('.mobile-nav-link[href]').forEach(link => {
      link.addEventListener('click', closeDrawer);
    });
  }

  // Scroll reveal
  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) { entry.target.classList.add('visible'); observer.unobserve(entry.target); }
    });
  }, { threshold: 0.08, rootMargin: '0px 0px -40px 0px' });
  document.querySelectorAll('.reveal').forEach(el => observer.observe(el));

  // Loading screen (landing page only)
  const screen = document.getElementById('loading-screen');
  if (screen) {
    const fontPromise = document.fonts ? document.fonts.ready : Promise.resolve();
    Promise.race([fontPromise, new Promise(r => setTimeout(r, 3000))]).then(() => {
      setTimeout(() => {
        screen.classList.add('hidden');
        screen.addEventListener('transitionend', () => screen.remove(), { once: true });
      }, 300);
    });
  }
});
