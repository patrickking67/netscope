# AGENTS.md

NetScope is a client-side network security toolkit: static HTML, CSS and vanilla JavaScript, no build step, no backend, no npm dependencies. The repository root is the published GitHub Pages site. Brand name is **NetScope**; paths and URLs are lowercase `netscope`.

## Commands (run from the repo root)

| Task | Command | Notes |
| --- | --- | --- |
| Full check | `npm run check` | Static site check, docs and text lint, then all unit tests. Run before every commit. |
| Unit tests only | `npm test` | node:test, Node 22+ |
| Static check only | `npm run check:static` | Same as `python3 scripts/check-static-site.py`; also runs in the deploy workflow |
| Preview | `npm run serve` | http://localhost:4102. Same server as `.claude/launch.json` (`netscope-site`). |

There is no install step. Do not add a bundler, framework or `node_modules`.

## Layout

```
index.html, pages/app.html, pages/about.html   Pages, each with its own CSP meta tag
assets/js/core.js        Pure logic, no DOM. Exposed as window.NetScopeCore and module.exports
assets/js/app.js         DOM wiring, network calls, rendering
assets/js/auth.js, firestore.js, firebase-config.js   Optional Firebase sign-in and cloud save
assets/js/theme-init.js, site.js, pwa.js   Theme before paint, landing/about behavior, SW registration
assets/css/style.css     All styles. Tokens at the top; light theme under [data-theme="light"]
sw.js                    Service worker. APP_SHELL list and CACHE_NAME
manifest.webmanifest     PWA manifest
tests/                   core.test.js, pages.test.js, service-worker.test.js
scripts/check-static-site.py   Asset links, JS syntax, required docs, llms.txt, launch.json, text lint
llms.txt                 Served at https://patrickking67.github.io/netscope/llms.txt
.claude/launch.json      Preview config (port 4102). The only tracked file under .claude/
```

## Conventions

- Logic that can be tested goes in `core.js`, takes `fetch` (or a DoH function) as an argument, and gets a test in `tests/core.test.js`. `app.js` renders.
- Render untrusted data with `esc()` (Core.escapeHtml) or `textContent`. Never interpolate API data raw into `innerHTML`.
- Third-party calls in `app.js` go through `timedFetch` (10 second timeout). `tests/pages.test.js` fails on a bare `fetch(` outside the speed test.
- Loading, empty, warning and error states use `statusHtml(message, kind)` and `setBusy(el, message)`.
- A failed lookup is an error, never a clean result.
- Plain text: sentence case, no em dashes, no emoji. The static check enforces the last two.

## Safety rules

- Content-Security-Policy: no inline scripts, no inline event handlers, no `javascript:` URLs. A new external origin must be added to the page's CSP on purpose (for the app, `connect-src` in `pages/app.html`) and called out in the PR. Tests check this.
- Passwords: only the 5-character SHA-1 prefix leaves the browser. Never store, log or export a password or full hash.
- No analytics or telemetry.
- When you change any file listed in `APP_SHELL`, bump `CACHE_NAME` in `sw.js`.
- Do not test Firebase sign-in with real credentials. The Firebase web config is public by design; do not add other keys.
- Do not edit `LICENSE`, the GitHub Pages workflow's deploy steps, or repository settings without being asked.

## Shipping

1. Branch from `main` (`feat/`, `fix/`, `docs/`, `chore/`).
2. `npm run check` passes; check the change at http://localhost:4102 (phone width 375px too).
3. Add a line to `CHANGELOG.md` under `[Unreleased]`.
4. Conventional Commits, one logical change per commit, no AI attribution.
5. Open a PR to `main`. CI (`.github/workflows/ci.yml`) runs `npm run check`. Merging to `main` deploys through `.github/workflows/static.yml`.

## Definition of done

`npm run check` is green, the behavior was checked in a browser, docs and CHANGELOG match the change, and no new origin was added without a CSP update.
