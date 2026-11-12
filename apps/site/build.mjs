/**
 * Static site generator: renders the landing page plus every markdown file in `/docs`
 * into a deployable `dist/` (no framework, one dev dependency).
 *
 *   node build.mjs        # -> dist/index.html, dist/docs/*.html, dist/styles.css
 */
import { readFileSync, writeFileSync, mkdirSync, rmSync, readdirSync, existsSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import { marked } from "marked";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const OUT = join(HERE, "dist");
const DOCS = join(ROOT, "docs");

const SITE_NAME = "Tessera";
const TAGLINE = "Proof of action for AI agents";
const EXCLUDED_DIRS = new Set(["strategy"]);
const EXCLUDED_FILES = new Set([
  "fundraise.md",
  "interview-guide.md",
  "governance-plane-plan.md",
  "data-moat.md",
]);

rmSync(OUT, { recursive: true, force: true });
mkdirSync(join(OUT, "docs"), { recursive: true });

// ── collect markdown sources ────────────────────────────────────────────────
function listMarkdown(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    if (entry.isDirectory() && EXCLUDED_DIRS.has(entry.name)) return [];
    if (!entry.isDirectory() && EXCLUDED_FILES.has(entry.name)) return [];
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
<link rel="stylesheet" href="../styles.css" />
</head>
<body class="doc">
${nav(slug)}
<main class="content">${body}</main>
<script>
  const search = document.getElementById("doc-search");
  search?.addEventListener("input", () => {
    const q = search.value.trim().toLowerCase();
    document.querySelectorAll(".sidebar li").forEach((item) => {
      item.style.display = !q || item.textContent.toLowerCase().includes(q) ? "" : "none";
    });
  });
</script>
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
writeFileSync(join(OUT, "styles.css"), readFileSync(join(HERE, "src", "styles.css")));
writeFileSync(join(OUT, "index.html"), readFileSync(join(HERE, "src", "index.html")));

console.log(`built ${sources.length} docs + landing -> ${relative(ROOT, OUT)}/`);
