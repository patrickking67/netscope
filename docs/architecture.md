# Architecture

NetScope is a zero-build static web application deployed directly from the repository root.

- `index.html` introduces the product and routes visitors into the toolkit.
- `pages/app.html` provides the interactive network tools.
- `assets/js/core.js` holds the pure logic (k-anonymity hashing, breach response parsing, DNS and email-security grading, WebRTC candidate analysis, generator entropy, speed math). It has no DOM access and takes `fetch` as an argument, so `tests/core.test.js` runs it in Node.
- `assets/js/app.js` wires the DOM, makes the network calls and renders results through `core.js`.
- `assets/js/auth.js` and `assets/js/firestore.js` provide optional account persistence.
- `assets/css/style.css` owns the responsive visual system.
- `sw.js` caches the app shell. It only handles same-origin GET requests inside its scope, so third-party API responses are never cached.

Each page sets a Content-Security-Policy in a meta tag. Inline scripts are not allowed, so page scripts live in `assets/js/`. Adding a new API host means adding it to `connect-src` in `pages/app.html`; `tests/pages.test.js` fails if a host the code calls is missing.

Core tools work without an account. Optional authentication and cloud save use Firebase. Third-party network APIs are called directly from the browser, so adding or changing providers requires a privacy and failure-mode review.
