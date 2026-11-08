# netscope

A client-side network security toolkit. Static HTML, CSS, and JavaScript with no build step or application backend.

## Run & Deploy

```bash
# Local dev: serve the root directory
python3 -m http.server 8000
# then visit http://localhost:8000

# Or any static server (caddy, http-server, etc.). No npm install needed.

# Tests (Node 22+, no dependencies)
npm test
```

Deploy is automatic via `.github/workflows/static.yml`. Pushes to `main` go live at https://patrickking67.github.io/netscope/.

## Architecture

- `index.html`: main entry and navigation shell.
- `pages/`: application and about pages.
- `assets/`: styles, scripts, images, logos, and fonts.
- `docs/`: architecture and Firebase setup.

Brand name is **NetScope** (capital N, capital S). Repository / URL paths are lowercase `netscope`.

## Code Conventions

- Vanilla JavaScript only; no frameworks, no bundler.
- Privacy-preserving APIs (such as HIBP k-anonymity). Never send full passwords or full hashes.
- All processing client-side; no telemetry, no analytics calls.
- Run `npm test` and `python3 scripts/check-static-site.py` before committing. Neither needs an install step.
- Put pure logic in `assets/js/core.js` with tests in `tests/`. No inline scripts: the CSP forbids them.
- Do not commit credentials or user-local agent state.
