# Tessera site

Static main page + docs site generated from `/docs` (one dev dependency: `marked`).

```bash
cd apps/site
pnpm install
pnpm build
```

Output:

- `dist/index.html` — main marketing page
- `dist/landing.css` — main-page styles
- `dist/docs/*.html` — generated documentation
- `dist/styles.css` — docs styles
- `dist/sitemap.xml`, `dist/robots.txt`, `dist/favicon.svg`, `dist/og.png`

## Local preview

```bash
pnpm build
python3 -m http.server -d dist 8090
# http://localhost:8090
```

To point the CTAs at local services instead of production:

```bash
SITE_URL=http://localhost:8090 \
APP_URL=http://localhost:8080 \
VERIFY_URL=http://localhost:8080/verify/ \
pnpm build
```

## Sources

- `src/index.html` — main page
- `src/landing.css` — main-page CSS
- `src/styles.css` — docs layout/CSS
- `src/og.html` — source for the 1200×630 OG image
- `src/icon.html` — source for the 180×180 apple-touch icon
- `public/` — favicon, manifest, generated PNG assets
- `build.mjs` — renders docs, replaces CTA placeholders, copies assets, and writes sitemap/robots

## Main-page rules

- No fake customer logos or testimonials.
- Use “tamper-evident” and “independently verifiable,” not “tamper-proof” or “immutable.”
- Do not claim SOC 2 certification or a completed pen test.
- Keep the product at `app.thetessera.xyz`; `/app` and `/login` redirect there.
- Keep the verifier at `verify.thetessera.xyz`; `/verify` redirects there.
- Keep exact test counts out of the page; use “300+ tests.”
