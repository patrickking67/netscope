# NetScope

A lightweight, client-side network security toolkit. No backend, no build step, no frameworks.

**[Live Demo](https://patrickking67.github.io/NetScope/)**

## Features

- **IP & Geolocation** -- Detect your public IP, ISP, ASN, proxy/VPN status, and map your approximate location
- **Speed Test** -- Measure download, upload, and ping with animated gauges
- **Breach Check** -- Check emails (XposedOrNot API) and passwords (HIBP k-anonymity) against known breaches
- **Password Generator** -- Generate strong passwords with configurable length, character sets, and strength meter
- **DNS & Security Scan** -- Lookup DNS records, check SPF/DMARC/DKIM, DNSSEC, and WebRTC leak detection
- **Run All** -- Execute every test in sequence with one click
- **Export** -- Copy results, share via email, or download a PDF report
- **Dark / Light Theme** -- Toggle between themes with persistent preference
- **Google Sign-In** -- Optional authentication via Firebase
- **Cloud Save** -- Save and retrieve test results across devices (requires sign-in)
- **Loading Screen** -- Animated splash screen on initial load

## Tech

Pure HTML, CSS, and JavaScript. Zero build step -- the repo root is the deployable output.

**APIs & Services:**

| Feature | Provider |
|---------|----------|
| IP Detection | [ipify](https://www.ipify.org/) |
| Geolocation | [ipapi.co](https://ipapi.co/) / [ipwho.is](https://ipwho.is/) |
| Password Breach | [HIBP Pwned Passwords](https://haveibeenpwned.com/API/v3#PwnedPasswords) |
| Email Breach | [XposedOrNot](https://xposedornot.com/) |
| DNS Lookup | [Google DNS-over-HTTPS](https://dns.google/) |
| Maps | [Leaflet](https://leafletjs.com/) + [OpenStreetMap](https://www.openstreetmap.org/) |
| Speed Test | [Cloudflare](https://speed.cloudflare.com/) |
| Auth & Database | [Firebase](https://firebase.google.com/) (Google Sign-In + Firestore) |

## Project Structure

```
NetScope/
├── .github/
│   └── workflows/
│       └── static.yml          # GitHub Pages deployment
├── css/
│   └── style.css               # All styles
├── docs/
│   └── FIREBASE_SETUP.md       # Firebase setup guide
├── images/
│   ├── bg-pattern.svg          # Subtle background dot pattern
│   ├── favicon.svg             # SVG favicon
│   ├── logo-dark.svg           # Logo for dark theme
│   ├── logo-icon.svg           # Icon-only logo
│   ├── logo-light.svg          # Logo for light theme
│   └── social-preview.png      # Open Graph preview image
├── js/
│   ├── app.js                  # Main application logic
│   ├── auth.js                 # Google Sign-In flow
│   ├── firebase-config.js      # Firebase project config
│   └── firestore.js            # Cloud save/load logic
├── .gitignore
├── about.html                  # About page
├── index.html                  # Main app
├── LICENSE                     # MIT
└── README.md
```

## Privacy

- Passwords are SHA-1 hashed locally; only the first 5 hash characters are sent (k-anonymity)
- All processing happens in your browser
- No analytics or tracking
- Sign-in is optional -- the app works fully without it
- If signed in, saved results are stored in your private Firestore collection

## Getting Started

```bash
# Clone
git clone https://github.com/patrickking67/NetScope.git
cd NetScope

# Serve locally
npx serve .
```

To set up Firebase for your own fork, see [docs/FIREBASE_SETUP.md](docs/FIREBASE_SETUP.md).

## Deployment

NetScope deploys automatically to GitHub Pages via the included GitHub Actions workflow (`.github/workflows/static.yml`). Push to `main` and the site updates within minutes.

To deploy your own fork:

1. Fork the repository
2. Enable GitHub Pages in **Settings > Pages** (source: GitHub Actions)
3. Push to `main` -- the workflow handles the rest

## License

[MIT](LICENSE)
