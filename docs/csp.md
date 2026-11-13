# Content Security Policy

The production Caddy configuration sends an enforced CSP (not report-only):

- `default-src 'self'`
- `script-src 'self'` plus a SHA-256 allowlist for the landing page's JSON-LD block
- `style-src 'self' 'unsafe-inline'` (React/Vite inline style attributes; no remote styles)
- `img-src 'self' data:`, `font-src 'self'`, `connect-src 'self'`
- `object-src 'none'`, `base-uri 'self'`, `frame-ancestors 'none'`
- `form-action 'self' mailto:`, `upgrade-insecure-requests`

The docs search script was moved out of each generated page into `/doc-search.js`; only the
static JSON-LD block remains inline. `scripts/check-csp-hash.mjs` verifies the hash against the
landing source and the Caddyfile.

```bash
node scripts/check-csp-hash.mjs
```

If the JSON-LD content changes, update the hash in `infra/docker/Caddyfile.prod` and the live
Caddyfile, then validate and reload Caddy. Do not add `'unsafe-inline'` to `script-src` as a
shortcut. Auth0 redirects are top-level navigations, not scripts; `connect-src 'self'` remains
sufficient for the portal API calls.
