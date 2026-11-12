# Architecture

NetScope is a static web application with no build step and no backend. The repository root is the published GitHub Pages site. All logic runs in the browser; the only servers involved are GitHub Pages (for the files) and the public APIs each tool calls directly.

## Components

```mermaid
flowchart TB
    subgraph pages["Pages (each with its own CSP meta tag)"]
        landing["index.html"]
        app["pages/app.html"]
        about["pages/about.html"]
    end
    subgraph scripts["assets/js"]
        core["core.js: pure logic, no DOM"]
        appjs["app.js: DOM, network calls, rendering"]
        auth["auth.js and firestore.js: optional sign-in and cloud save"]
        site["site.js and theme-init.js: page chrome and theme"]
        pwa["pwa.js: registers the service worker"]
    end
    sw["sw.js: app shell cache"]
    tests["tests/: node:test suites"]
    app --> appjs
    app --> auth
    appjs --> core
    landing --> site
    about --> site
    pages --> pwa
    pwa --> sw
    tests -. "require()" .-> core
    tests -. "vm sandbox" .-> sw
    tests -. "read as text" .-> pages
```

What to notice: `core.js` is the only place with real logic, and it has no DOM access. It is a classic script that also sets `module.exports`, so the browser loads it with a `<script>` tag and the tests load the same file with `require()`. Anything in it that talks to the network takes `fetch` (or a DNS-over-HTTPS function) as an argument, which is what lets the tests record exactly what would leave the browser.

## Trust boundaries

```mermaid
flowchart LR
    subgraph browser["Browser: first-party code, trusted"]
        input["What you type: password, email, domain, token, subnet"]
        core["core.js"]
        store["localStorage: theme, guest flag and session flag only"]
        input --> core
    end
    subgraph third["Third parties: receive the minimum"]
        hibp["Have I Been Pwned"]
        xon["XposedOrNot"]
        doh["dns.google"]
        ipp["IP and geolocation providers"]
        cf["Cloudflare speed endpoints"]
    end
    subgraph optional["Optional, only after sign-in"]
        fb["Firebase Auth and Firestore"]
    end
    core -- "5 hex characters of a SHA-1 hash" --> hibp
    core -- "email address" --> xon
    core -- "domain name" --> doh
    core -- "nothing typed; the request reveals your IP" --> ipp
    core -- "random bytes" --> cf
    core -. "IP, speed, scan and email results when you press Save" .-> fb
```

What to notice: a password, a JWT and a subnet never cross the browser boundary in any form except the 5-character hash prefix. The app page's `connect-src` lists exactly these hosts, and `tests/pages.test.js` fails if the code calls a host that is not listed. Firebase is the only place results are stored, and only when a signed-in user presses Save; `firestore.js` picks named fields and has no password or token field to pick.

## The k-anonymity password check

```mermaid
sequenceDiagram
    participant Page as Browser (core.js)
    participant HIBP as api.pwnedpasswords.com
    Page->>Page: sha1Hex(password)
    Page->>Page: splitPwnedHash: prefix (5) and suffix (35)
    Page->>HIBP: GET /range/{prefix}, header Add-Padding: true
    alt HTTP error or timeout
        HIBP-->>Page: error
        Page->>Page: throw, so the UI shows an error and never "not found"
    else 200 OK
        HIBP-->>Page: lines of SUFFIX:COUNT, padded with zero-count rows
        Page->>Page: parsePwnedRange(body, suffix)
        Page->>Page: passwordCheckSummary: found or not, strength 1 to 5
    end
```

What to notice: `buildPwnedRangeUrl` throws on anything that is not exactly five uppercase hex characters, so a coding mistake cannot send a full hash. The error branch matters as much as the happy path: a failed lookup throws instead of returning zero, so a rate limit is never shown as a safe password. The summary that reaches the report holds a boolean and a score, not the breach count, because a count can identify a common password.

## The domain scan and grade

```mermaid
flowchart TB
    input["normalizeDomainInput: domain, URL or email"] --> fan["28 DNS-over-HTTPS queries in parallel"]
    fan --> status{"Did the A, AAAA, MX and NS lookups work?"}
    status -- "all failed" --> err["status: error. Nothing is graded"]
    status -- "NXDOMAIN" --> nx["status: nxdomain. Nothing is graded"]
    status -- "at least one answered" --> eval["Evaluate SPF, DMARC, DKIM, DNSSEC, MX, MTA-STS, TLS-RPT, BIMI"]
    eval --> unknown{"Did this check's own lookup fail?"}
    unknown -- "yes" --> mark["warn, marked unknown"]
    unknown -- "no" --> result["pass, warn, fail or info, with a fix when not pass"]
    mark --> grade["gradeChecks"]
    result --> grade
    grade --> out["Score out of 100, letter A to F, points lost per check, incomplete flag"]
```

What to notice: the scan separates "the record is missing" from "the lookup failed". A missing SPF record costs 30 points; an SPF lookup that timed out costs nothing and sets `incomplete`. The 28 queries are 4 record types, 6 policy records and 18 common DKIM selectors, all settled with `Promise.all` so one slow answer does not hold up the rest. Optional controls (MTA-STS, TLS-RPT, BIMI, an undiscovered DKIM selector) report as info and never lower the grade.

## The service worker

```mermaid
flowchart TB
    req["fetch event"] --> cacheable{"GET, http(s), and inside this worker's scope?"}
    cacheable -- "no" --> pass["Not intercepted. API calls go straight to the network"]
    cacheable -- "yes" --> nav{"Navigation?"}
    nav -- "yes" --> net["Network first"]
    net -- "ok" --> put["Cache the page, return it"]
    net -- "offline" --> shell["Cached page, or the cached app page"]
    nav -- "no" --> swr["Stale while revalidate"]
    swr --> store{"Response ok and same-origin?"}
    store -- "yes" --> update["Refresh the cache"]
    store -- "no" --> skip["Return it, do not store it"]
```

What to notice: the first decision is the privacy property. Breach, IP, DNS and speed requests are third-party, so they fail the scope check and are never cached. GitHub Pages serves every project of an account from one origin, which is why the check is the worker's scope and not just the origin. Error pages are not stored, so a bad deploy cannot poison the cache.

## Local tools

The password generator, subnet calculator and JWT inspector make no network request. The subnet calculator uses plain numbers for IPv4 and `BigInt` for IPv6, and prints IPv6 in RFC 5952 form. The JWT inspector decodes base64url with a fatal UTF-8 decoder, never verifies the signature (it says so in every result), and hands the report only an algorithm name, a status and finding names through `jwtReportSummary`.

## Rules that follow from this design

- New logic goes in `core.js` with a test. `app.js` renders.
- A new API host must be added to `connect-src` in `pages/app.html` on purpose. The tests fail otherwise.
- Changing a file in the app shell means bumping `CACHE_NAME` in `sw.js`.
- Untrusted data (API responses, token claims, DNS records) is rendered with `escapeHtml` or `textContent`.
