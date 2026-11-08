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
- Anything that would send more data to a third party than the README privacy model says, for example a full password or full hash leaving the browser
- Content-Security-Policy bypasses, XSS through rendered API data, or the service worker caching third-party responses
- Firestore rules or auth flows that let one user read another user's saved results

Out of scope:

- Vulnerabilities in the third-party services themselves (ipify, ipapi.co, ipwho.is, freeipapi.com, Cloudflare, XposedOrNot, Have I Been Pwned, Google DNS, Firebase)
- The public Firebase web config, which identifies the client app and is not a secret
- Denial of service against GitHub Pages

## Security model

NetScope performs its core calculations in the browser. External services receive only the minimum each check needs. Password checks use the Have I Been Pwned k-anonymity range API and never transmit a plaintext password or full hash. Every page sets a strict Content-Security-Policy that forbids inline scripts, and CDN scripts are pinned with Subresource Integrity. Authorization for the optional cloud save is enforced by Firebase Authentication and Firestore Security Rules.
