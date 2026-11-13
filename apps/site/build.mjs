/**
 * Static site generator: renders the landing page plus every markdown file in `/docs`
 * into a deployable `dist/` (no framework, one dev dependency).
 *
 *   node build.mjs        # -> dist/index.html, dist/docs/*.html, dist/landing.css
 */
import {
  copyFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import { marked } from "marked";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const OUT = join(HERE, "dist");
const DOCS = join(ROOT, "docs");

const SITE_NAME = "Tessera";
const TAGLINE = "Proof of action for AI agents";
const SITE_URL = (process.env.SITE_URL ?? "https://thetessera.xyz").replace(/\/$/, "");
const APP_URL = `${(process.env.APP_URL ?? "https://app.thetessera.xyz").replace(/\/$/, "")}/`;
const VERIFY_URL = `${(process.env.VERIFY_URL ?? "https://verify.thetessera.xyz/verify/").replace(/\/$/, "")}/`;
const GITHUB_URL = (process.env.GITHUB_URL ?? "https://github.com/lexagor/tessera").replace(
  /\/$/,
  "",
);
const PARTNER_EMAIL = process.env.PARTNER_EMAIL ?? "partners@thetessera.xyz";
const SECURITY_EMAIL = process.env.SECURITY_EMAIL ?? "security@thetessera.xyz";
const PUBLIC_DOCS = new Set(
  JSON.parse(readFileSync(join(HERE, "public-docs.json"), "utf8")),
);

rmSync(OUT, { recursive: true, force: true });
mkdirSync(join(OUT, "docs"), { recursive: true });

// ── collect markdown sources ────────────────────────────────────────────────
function listMarkdown(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) return listMarkdown(full);
    return entry.name.endsWith(".md") ? [full] : [];
  });
}

function slugOf(file) {
  const rel = relative(DOCS, file).replace(/\.md$/, "");
  return rel.split(/[\\/]/).join("-");
}

/** Rewrite intra-doc markdown links to generated .html links. */
function rewriteLinks(html) {
  return html
    .replace(/href="([^"]+?)\.md"/g, (_, p) => `href="${p.split("/").join("-")}.html"`)
    .replace(/href="\.\.\/([^"]+?)\.md"/g, (_, p) => `href="${p.split("/").join("-")}.html"`);
}

const sources = listMarkdown(DOCS)
  .map((file) => ({ file, slug: slugOf(file), title: titleOf(file) }))
  .filter((source) => PUBLIC_DOCS.has(source.slug))
  .sort((a, b) => a.slug.localeCompare(b.slug));

if (sources.some((s) => relative(DOCS, s.file).startsWith("strategy/"))) {
  throw new Error("refusing to publish the confidential strategy pack");
}

function titleOf(file) {
  const text = readFileSync(file, "utf8");
  const heading = text.match(/^#\s+(.+)$/m);
  return heading ? heading[1].trim() : file.split("/").pop().replace(/\.md$/, "");
}

// ── layout ──────────────────────────────────────────────────────────────────
function nav(currentSlug) {
  const items = sources
    .map(
      (s) =>
        `<li><a href="${s.slug}.html"${
          s.slug === currentSlug ? ' class="active"' : ""
        }>${escapeHtml(s.title)}</a></li>`,
    )
    .join("");
  return `<nav class="sidebar"><a class="brand" href="../index.html">${SITE_NAME}</a>
    <p class="tagline">${TAGLINE}</p>
    <input id="doc-search" class="doc-search" type="search" placeholder="Search docs" aria-label="Search docs" />
    <ul>${items}</ul>
    <p class="links"><a href="index.html">Docs home</a></p></nav>`;
}

function page(title, body, slug) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${escapeHtml(title)} · ${SITE_NAME}</title>
<meta name="description" content="${escapeHtml(title)} — Tessera documentation." />
<link rel="canonical" href="${SITE_URL}/docs/${slug}.html" />
<link rel="icon" href="/favicon.svg" type="image/svg+xml" />
<link rel="stylesheet" href="../styles.css" />
</head>
<body class="doc">
${nav(slug)}
<main class="content">${body}</main>
<script src="../doc-search.js" defer></script>
</body>
</html>`;
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// ── render docs ─────────────────────────────────────────────────────────────
for (const { file, slug, title } of sources) {
  const md = readFileSync(file, "utf8");
  const html = rewriteLinks(marked.parse(md));
  writeFileSync(join(OUT, "docs", `${slug}.html`), page(title, html, slug));
}

const docsIndex = `# Documentation

${sources.map((s) => `- [${escapeHtml(s.title)}](${s.slug}.html)`).join("\n")}
`;
writeFileSync(
  join(OUT, "docs", "index.html"),
  page("Documentation", marked.parse(docsIndex), "index"),
);

// ── landing + assets ────────────────────────────────────────────────────────
function renderLanding() {
  const replacements = {
    SITE_URL,
    APP_URL,
    VERIFY_URL,
    GITHUB_URL,
    PARTNER_EMAIL,
    SECURITY_EMAIL,
  };
  let html = readFileSync(join(HERE, "src", "index.html"), "utf8");
  for (const [name, value] of Object.entries(replacements)) {
    html = html.replaceAll(`%%${name}%%`, value);
  }
  return html;
}

function escapeXml(value) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

writeFileSync(join(OUT, "index.html"), renderLanding());
copyFileSync(join(HERE, "src", "landing.css"), join(OUT, "landing.css"));
copyFileSync(join(HERE, "src", "styles.css"), join(OUT, "styles.css"));
copyFileSync(join(HERE, "src", "doc-search.js"), join(OUT, "doc-search.js"));
if (existsSync(join(HERE, "public"))) {
  cpSync(join(HERE, "public"), OUT, { recursive: true });
}

const sitemapUrls = [
  `${SITE_URL}/`,
  `${SITE_URL}/docs/index.html`,
  `${SITE_URL}/proof/`,
  `${SITE_URL}/proof/live-denial.html`,
  `${SITE_URL}/proof/sandbox-action.html`,
  ...sources.map((source) => `${SITE_URL}/docs/${source.slug}.html`),
];
writeFileSync(
  join(OUT, "sitemap.xml"),
  `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${sitemapUrls.map((url) => `  <url><loc>${escapeXml(url)}</loc></url>`).join("\n")}
</urlset>
`,
);
writeFileSync(
  join(OUT, "robots.txt"),
  `User-agent: *
Allow: /

Sitemap: ${SITE_URL}/sitemap.xml
`,
);

console.log(`built ${sources.length} docs + landing -> ${relative(ROOT, OUT)}/`);
