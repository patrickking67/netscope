# Security policy

## Supported versions

NetScope is a static site deployed from `main`. Only the current deployment at https://patrickking67.github.io/netscope/ and the latest commit on `main` are supported.

## Reporting a vulnerability

Report privately through GitHub security advisories:
https://github.com/patrickking67/netscope/security/advisories/new

Do not open a public issue with exploit details, tokens, personal data or credentials. I aim to acknowledge a report within 7 days and to share a fix or a plan within 30 days.

## Scope

In scope:

- The pages, scripts and service worker in this repository
- Anything that would send more data to a third party than the table below says, for example a full password or full hash leaving the browser
- Content-Security-Policy bypasses, XSS through rendered API data, or the service worker caching third-party responses
- Firestore rules or auth flows that let one user read another user's saved results

Out of scope:

- Vulnerabilities in the third-party services themselves (ipify, ipapi.co, ipwho.is, freeipapi.com, Cloudflare, XposedOrNot, Have I Been Pwned, Google DNS, Firebase)
- The public Firebase web config, which identifies the client app and is not a secret
- Denial of service against GitHub Pages

## What each check sends

| Check | Leaves your browser | Never leaves your browser |
| --- | --- | --- |
| Password breach | The first 5 hex characters of the SHA-1 hash, sent to `api.pwnedpasswords.com/range/{prefix}` with `Add-Padding: true` so the response size does not hint at the result | The password, the full hash, the 35-character suffix used for matching |
| Email breach | The email address, sent to XposedOrNot (that is how their lookup works) | Nothing is stored by NetScope |
| IP and location | Your IP reaches each provider as part of the request; the geolocation providers also receive it in the URL | |
| DNS scan | The domain name, sent to `dns.google` | |
| WebRTC check | A STUN request to `stun.l.google.com` | Local candidates are inspected in the page and only shown to you |
| Speed test | Random test payloads to and from Cloudflare | |
| Password generator | Nothing | Everything |
| Subnet calculator | Nothing | Everything |
| JWT inspector | Nothing | The token, its claims and its signature. The exported report keeps only the algorithm, the validity status and the names of the findings |

Cloud save is opt-in. If you sign in and press Save, the results (IP, city, country, ISP and coordinates, speed, scanned domain and checks, and the checked email address with its breach count) are written to `users/{uid}/results` in Firestore. Passwords and tokens are never saved. The Firebase SDK is loaded from Google's CDN on the app page even for guests.

## Security model

NetScope performs its core calculations in the browser. External services receive only the minimum each check needs. Password checks use the Have I Been Pwned k-anonymity range API and never transmit a plaintext password or full hash. The JWT inspector decodes only and does not verify signatures. Every page sets a strict Content-Security-Policy that forbids inline scripts, and CDN scripts are pinned with Subresource Integrity. Authorization for the optional cloud save is enforced by Firebase Authentication and Firestore Security Rules.
