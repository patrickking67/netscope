# Changelog

All notable changes to NetScope are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/). There are no tagged releases yet; `package.json` is at 1.0.0.

## [Unreleased]

### Added
- Subnet calculator: network, mask, wildcard, broadcast, usable range, size and address type for IPv4 (prefix or dotted mask, /31 and /32 handled) and IPv6 (BigInt math, RFC 5952 text). Runs in the page with no network request and is included in the exported report.
- JWT inspector: decodes a token's header and payload in the page and flags `alg: none`, a missing or empty signature, shared-secret algorithms, key hints in the header, missing or passed expiry, and long lifetimes. The token is never sent, saved or exported; the report keeps only the algorithm, status and finding names. The signature is not verified.
- Tool tabs have accessible names when they collapse to icons on phones.
- The domain scan gives a letter grade (A to F) with a score out of 100, says where points were lost, and adds a "How to fix" line under every problem. The grade and fixes are in the exported report. A lookup that fails marks the grade incomplete instead of lowering it.
- DNS & Security scan checks MTA-STS, SMTP TLS reporting (TLS-RPT) and BIMI, probes 18 common DKIM selectors in parallel and lists every one it finds.
- One overall verdict for a scan (looks good, needs attention, at risk) with counts, and a plain-language explanation under each check.
- The text, email and PDF export includes the scan verdict and the email breach result.
- The export includes a password check section with only breach found or not and an estimated strength score. The password, its hash and the breach count are never exported. The password result also shows the strength score.
- Skip links, a `<main>` landmark on every page, ARIA tabs with arrow-key navigation, live result regions and names for icon-only controls.
- `npm run check` runs the static site check (including a text lint) and the unit tests in one command.
- `.claude/launch.json` for the local preview on port 4102, `llms.txt`, CONTRIBUTING.md, this changelog, editor and git attribute files, CODEOWNERS, Dependabot, and issue and pull request templates.

### Changed
- Landing page: a real screenshot of the app in the hero, a diagram of the k-anonymity password check, and a section listing what the checks enforce, with links to the tests and CI. The footer links the source, architecture notes, security policy and the author's profile.
- New 1200x630 Open Graph image built from the real interface.
- Service worker cache bumped to `netscope-shell-v5` for the new tools and landing page.
- Speed test requests have deadlines (2 seconds per ping, 8 seconds for latency, 3 seconds past each 12-second transfer phase), so a stalled connection ends with partial results instead of hanging. A Cancel button stops the test and keeps what was measured.
- IP, breach and DNS requests time out after 10 seconds instead of hanging, and IP echo responses must be a valid address.
- DMARC with `pct` under 100 is a warning, not a pass. A null MX record is reported as "does not accept email".
- Loading, empty, warning and error states look and read the same across tools. Result icons are SVG instead of emoji.
- Muted text, status colors and primary buttons meet WCAG AA contrast in both themes. Focus rings are visible and reduced-motion preferences are respected.
- Labels are sentence case, the landing badge says what the app does, and per-section scroll animations are gone.
- On phones the Full Scan button collapses to an icon so the header no longer clips.

### Fixed
- Scanning a domain that does not exist now says so instead of grading missing SPF and DMARC as failures.
- A failed DNS lookup is reported as "could not look up" instead of "no record found".
- Password generator options were unreachable by keyboard.

## 2026-11-07

### Fixed
- Breach, DNS and WebRTC results: failed or rate-limited lookups are errors, never "no breaches found"; SPF and DMARC edge cases; the normal STUN public address is no longer flagged as a leak.

### Added
- Content-Security-Policy on every page and SRI on CDN scripts.
- CI that runs the static check and unit tests on every push and pull request.

### Changed
- README rewritten with the actual tools and a per-check privacy model.

## 2026-07-13

### Added
- Installable PWA with an offline app shell.

### Changed
- Hardened the GitHub Pages release workflow and updated the official deployment actions.

## 2026-05-13

### Changed
- Lowercase canonical URLs and repository name; agent guide added.

## 2026-02-11 to 2026-02-12

### Added
- First public version: IP and geolocation, multi-connection speed test with progress, email and password breach checks, password generator with presets, DNS and email security scan, Full Scan, PDF export, light and dark themes, optional Firebase sign-in and cloud save, and a multi-page layout with landing and about pages.
