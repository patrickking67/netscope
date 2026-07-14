# Security policy

## Reporting

Use GitHub private vulnerability reporting when available. Do not open a public issue containing exploit details, tokens, personal data, or credentials.

## Security model

NetScope performs its core calculations in the browser. External network and breach services still receive the minimum query material needed for each feature. Password checks use the Have I Been Pwned k-anonymity protocol and must never transmit a plaintext password or full password hash.

Firebase web configuration identifies the public client application and is not an administrative credential. Authorization must be enforced by Firebase Authentication and Firestore Security Rules.
