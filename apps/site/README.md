# Tessera site

Static landing page + docs site generated from `/docs` (one dev dependency: `marked`).

```bash
cd apps/site
pnpm install
pnpm build        # -> dist/index.html, dist/docs/*.html, dist/styles.css
```

Deploy `dist/` to any static host (Caddy, GitHub Pages, Cloudflare Pages, S3). Locally:

```bash
python3 -m http.server -d dist 8080
# then open http://localhost:8080
```

- `src/index.html` — landing page (edit directly).
- `src/styles.css` — shared styles for landing + docs.
- `build.mjs` — renders every `docs/**/*.md` to `dist/docs/<slug>.html` with a nav sidebar and
  rewrites intra-doc `.md` links to `.html`.
