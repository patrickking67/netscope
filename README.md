<p align="center">
  <a href="https://patrickking67.github.io/netscope/">
    <img src="assets/images/logo-light.svg" alt="NetScope" height="60">
  </a>
</p>

<p align="center">
  <strong>An installable, client-side network security toolkit.</strong><br>
  Check your public IP and connection, test for breached credentials without giving them away, generate strong secrets, and grade a domain's DNS and email security. All from a static site with no backend.
</p>

<p align="center">
  <a href="https://patrickking67.github.io/netscope/"><img src="https://img.shields.io/badge/Live%20Demo-Visit%20Site-3b82f6?style=for-the-badge&logo=googlechrome&logoColor=white" alt="Live Demo"></a>
  <a href="https://github.com/patrickking67/netscope/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/patrickking67/netscope/ci.yml?branch=main&style=for-the-badge&logo=githubactions&logoColor=white&label=Tests" alt="Tests"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/patrickking67/netscope?style=for-the-badge&logo=opensourceinitiative&logoColor=white&color=10b981" alt="License"></a>
</p>

<p align="center">
  <a href="https://patrickking67.github.io/netscope/">
    <img src="assets/images/social-preview.png" alt="NetScope screenshot" width="720">
  </a>
</p>

---

## Why it exists

Most "check my connection" and "have I been breached" sites ask you to trust a server with exactly the data you are worried about. NetScope runs in your browser and talks only to the public APIs each check needs, sending the minimum each one requires. Passwords are hashed locally and only a 5-character hash prefix leaves the page.

It is plain HTML, CSS and JavaScript. The repository root is the deployed site: no framework, no bundler, no `node_modules`.

## Tools

The app (`pages/app.html`) has five tools plus a one-click Full Scan.

| Tool | What it checks | Service used |
| --- | --- | --- |
| **IP & Location** | Public IP, ISP, organization, ASN, IP version, proxy and hosting flags (when the provider reports them), approximate location on a map | ipify, seeip (IP); ipapi.co, ipwho.is, freeipapi.com (geolocation, tried in order); OpenStreetMap tiles |
| **Speed Test** | Ping and jitter (20 samples, outliers trimmed), then 12-second multi-connection download and upload with a 2-second warm-up | Cloudflare speed endpoints |
| **Breach Check: email** | Whether an address appears in known breaches, with the breach names | XposedOrNot |
| **Breach Check: password** | How many times a password appears in breach corpora, using k-anonymity | Have I Been Pwned Pwned Passwords |
| **Password Generator** | Random passwords, PINs, hex keys and 5-word passphrases, with strength computed from the generator's real entropy | None (Web Crypto) |
| **DNS & Security** | A, AAAA, MX and NS records; SPF (missing, duplicate, `+all`, `?all`); DMARC policy; DKIM at common selectors; DNSSEC validation; WebRTC local address and VPN leak check; whether the page is on HTTPS | Google DNS-over-HTTPS; Google STUN |

**Full Scan** runs IP, speed, email breach (if an address is entered or you are signed in) and DNS (if a domain is entered) in sequence. Results can be copied, emailed, or downloaded as a PDF (jsPDF). Optional sign-in (Google, GitHub or email via Firebase) adds cloud save of results and theme sync. Every tool works without an account.

## Privacy model

What each check sends, and to whom:

| Check | Leaves your browser | Never leaves your browser |
| --- | --- | --- |
| Password breach | The first 5 hex characters of the SHA-1 hash, sent to `api.pwnedpasswords.com/range/{prefix}` with `Add-Padding: true` so the response size does not hint at the result | The password, the full hash, the 35-character suffix used for matching |
| Email breach | The email address, sent to XposedOrNot (that is how their lookup works) | Nothing is stored by NetScope |
| IP & Location | Your IP reaches each provider as part of the request; the geolocation providers also receive it in the URL | |
| DNS scan | The domain name, sent to `dns.google` | |
| WebRTC check | A STUN request to `stun.l.google.com` | Local candidates are inspected in the page and only shown to you |
| Speed test | Random test payloads to and from Cloudflare | |
| Password generator | Nothing | Everything |

Other guarantees, each backed by code and tests:

- **Failed lookups are never reported as safe.** A rate-limited or failed breach lookup shows an error, not "no breaches found".
- **No telemetry.** No analytics, tracking pixels or third-party cookies.
- **Strict Content-Security-Policy.** Every page forbids inline scripts, `eval`, plugins and `<base>` changes, and the app page lists the exact API hosts it may contact. Leaflet and jsPDF are pinned with Subresource Integrity hashes.
- **The service worker never caches API responses.** It only stores same-origin files inside its own scope, so breach, IP and DNS results are never written to disk by the PWA.
- **Cloud save is opt-in.** If you sign in and press Save, the results (IP, city, country, ISP and coordinates, speed, scanned domain and checks, and the checked email address with its breach count) are written to `users/{uid}/results` in Firestore. Passwords are never saved or exported. The Firebase SDK is loaded from Google's CDN on the app page even for guests.

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## Run it locally

No install step. Any static file server works; this is the one the project uses:

```bash
git clone https://github.com/patrickking67/netscope.git
cd netscope
python3 -m http.server 8000
# open http://localhost:8000
```

Serve over HTTP rather than opening `index.html` from disk. Service workers and some browser APIs do not work on `file://` URLs.

## Install as an app (PWA)

NetScope ships a web app manifest and a service worker that caches the app shell.

- **Chrome or Edge (desktop):** open the [live site](https://patrickking67.github.io/netscope/pages/app.html) and use the install icon in the address bar or the browser menu's install option.
- **Android (Chrome):** menu, then **Add to Home screen** or **Install app**.
- **iOS and iPadOS (Safari):** Share, then **Add to Home Screen**.
- **macOS (Safari 17+):** File, then **Add to Dock**.

Once installed, the interface opens offline. The checks themselves need a network connection.

## Tests

Unit tests use Node's built-in test runner. No dependencies to install; Node 22 or newer.

```bash
npm test                              # 74 tests
python3 scripts/check-static-site.py  # asset links, JS syntax, PWA files
```

What is covered:

- **k-anonymity:** with a recording `fetch`, asserts only the 5-character prefix is sent and the password, full hash and suffix never appear in the request; HTTP errors throw instead of returning zero.
- **Breach parsing:** both XposedOrNot response shapes, 404 as clean, 429 and 5xx as errors, the network fallback.
- **DNS grading:** domain input normalization, quoted TXT joining, SPF and DMARC edge cases (including `sp=` not being mistaken for `p=`), revoked DKIM keys.
- **WebRTC:** candidate parsing, private ranges, and not flagging the normal STUN public address as a leak.
- **Generator:** rejection sampling (no modulo bias), entropy from pool size or word list size.
- **Speed math:** latency trimming and time-ordered jitter, throughput after warm-up.
- **Service worker:** loaded in a `vm` sandbox to check scope limits, error responses not cached, offline fallback, stale-while-revalidate, and that every page script is in the app shell.
- **Pages:** CSP present and strict on every page, no inline scripts or handlers, SRI on CDN scripts, every API host the code calls is in `connect-src`.

CI runs both commands on every push and pull request ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

## Project layout

```
index.html                  Landing page
pages/app.html              The toolkit
pages/about.html            About and privacy summary
assets/js/core.js           Pure logic: hashing, parsing, grading, entropy, speed math (unit tested)
assets/js/app.js            DOM wiring, network calls, rendering
assets/js/auth.js           Optional Firebase sign-in and saved-results panel
assets/js/firestore.js      Optional cloud save and preferences
assets/js/firebase-config.js  Public Firebase web config
assets/js/theme-init.js     Applies the saved theme before first paint
assets/js/site.js           Landing and about page interactions
assets/js/pwa.js            Service worker registration
sw.js                       Service worker (app shell cache)
manifest.webmanifest        PWA manifest
tests/                      node:test suites
scripts/check-static-site.py  Static validation used in CI and deploy
docs/                       Architecture notes and Firebase setup
```

`core.js` is a classic script that also exports through `module.exports`, so the browser loads it with a normal `<script>` tag and Node tests `require()` it without a build step.

## Deployment

Pushes to `main` deploy to GitHub Pages through [`.github/workflows/static.yml`](.github/workflows/static.yml), which runs the static checks first. To deploy a fork, set **Settings > Pages > Source** to **GitHub Actions** and push to `main`.

Firebase is optional. To use your own project, follow [docs/FIREBASE_SETUP.md](docs/FIREBASE_SETUP.md), then update the `frame-src` host in the CSP in `pages/app.html` to your `authDomain`.

## Credits

- [Have I Been Pwned](https://haveibeenpwned.com) for the Pwned Passwords range API.
- [XposedOrNot](https://xposedornot.com) for the free email breach API.
- [Ookla Speedtest](https://www.speedtest.net) inspired the multi-connection test and gauge.

## License

[MIT](LICENSE). Copyright (c) 2026 Patrick King.
