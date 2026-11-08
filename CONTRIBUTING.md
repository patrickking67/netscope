# Contributing

Thanks for helping. NetScope is a static site with no build step, so setup is short.

## Setup

You need Python 3 and Node.js 22 or newer. There is nothing to install.

```bash
git clone git@github.com:patrickking67/netscope.git
cd netscope
npm run check   # static checks, text lint and unit tests
npm run serve   # http://localhost:4102
```

## Branches

Branch from `main` and name the branch by type:

- `feat/<short-name>` for new features
- `fix/<short-name>` for bug fixes
- `docs/<short-name>` for documentation only
- `chore/<short-name>` for tooling, CI and housekeeping

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `style:`, `refactor:`, `test:`, `ci:`, `chore:`. Keep one logical change per commit and make sure each commit passes `npm run check`.

## Rules that keep the site safe

- No inline scripts or inline event handlers. Every page has a strict Content-Security-Policy and the tests fail if one slips in.
- A new external API host must be added to `connect-src` in `pages/app.html` on purpose, with a note in the PR about what data it receives.
- Never send a full password or full password hash anywhere. Passwords are not stored or exported.
- Put pure logic in `assets/js/core.js` and test it in `tests/`.
- If you change a file in the app shell, bump `CACHE_NAME` in `sw.js`.
- No em dashes or emoji in committed text. `npm run check` enforces this.

## Pull request checklist

- [ ] `npm run check` passes
- [ ] The change works in a browser at http://localhost:4102
- [ ] CSP updated on purpose if a new origin is needed
- [ ] `CACHE_NAME` bumped if an app shell file changed
- [ ] CHANGELOG.md updated under `[Unreleased]`
