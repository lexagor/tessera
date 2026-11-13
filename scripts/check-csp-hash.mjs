#!/usr/bin/env node
/** Verify the inline JSON-LD hash in the Caddy CSP matches the landing page source. */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const source = readFileSync(new URL("../apps/site/src/index.html", import.meta.url), "utf8");
const start = source.indexOf('<script type="application/ld+json">');
if (start < 0) throw new Error("JSON-LD script not found");
const bodyStart = start + '<script type="application/ld+json">'.length;
const end = source.indexOf("</script>", bodyStart);
const hash = `sha256-${createHash("sha256").update(source.slice(bodyStart, end)).digest("base64")}`;
const caddy = readFileSync(new URL("../infra/docker/Caddyfile.prod", import.meta.url), "utf8");
if (!caddy.includes(hash)) {
  console.error(`Caddy CSP is missing ${hash}`);
  process.exit(1);
}
console.log(`CSP hash matches: ${hash}`);
