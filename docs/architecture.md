# Architecture

NetScope is a zero-build static web application deployed directly from the repository root.

- `index.html` introduces the product and routes visitors into the toolkit.
- `pages/app.html` provides the interactive network tools.
- `assets/js/app.js` owns client-side network checks and interface state.
- `assets/js/auth.js` and `assets/js/firestore.js` provide optional account persistence.
- `assets/css/style.css` owns the responsive visual system.

Core tools work without an account. Optional authentication and cloud save use Firebase. Third-party network APIs are called directly from the browser, so adding or changing providers requires a privacy and failure-mode review.
