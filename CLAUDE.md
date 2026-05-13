# netscope

A client-side network security toolkit. Static HTML / CSS / JavaScript — no build step, no backend.

## Run & Deploy

```bash
# Local dev: serve the root directory
python3 -m http.server 8000
# then visit http://localhost:8000

# Or any static server (caddy, http-server, etc.). No npm install needed.
```

Deploy is automatic via `.github/workflows/static.yml` — pushes to `main` go live at https://patrickking67.github.io/netscope/.

## Architecture

- `index.html` — main entry, navigation shell.
- `pages/` — per-tool pages (IP info, breach check, DNS, password gen, speed test).
- `assets/` — images, logos, fonts.
- `docs/` — supplementary docs and screenshots.

Brand name is **NetScope** (capital N, capital S). Repository / URL paths are lowercase `netscope`.

## Code Conventions

- Vanilla JavaScript only; no frameworks, no bundler.
- Privacy-preserving APIs (e.g. HIBP k-anonymity) — never send full passwords or full hashes.
- All processing client-side; no telemetry, no analytics calls.
- One feature per `pages/` subdirectory.
