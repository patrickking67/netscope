# netscope

A client-side network security toolkit. Static HTML, CSS, and JavaScript with no build step or application backend.

## Run & Deploy

```bash
# Local dev: serve the root directory
python3 -m http.server 8000
# then visit http://localhost:8000

# Or any static server (caddy, http-server, etc.). No npm install needed.
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
- Run `python3 scripts/check-static-site.py` before committing.
- Do not commit credentials or user-local agent state.
