#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const manifestPath = process.env.PROOF_MANIFEST ?? "apps/site/public/proof/manifest.json";
const base = process.env.PROOF_BASE_URL?.replace(/\/$/, "");
const localRoot = join(process.cwd(), "apps/site/public");
const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
const failures = [];

if (manifest.version !== 1) failures.push("manifest version must be 1");
if (!Array.isArray(manifest.artifacts) || manifest.artifacts.length === 0) {
  failures.push("manifest has no artifacts");
}

function safePath(path) {
  if (typeof path !== "string" || !path.startsWith("/proof/") || path.includes("..")) {
    throw new Error(`unsafe proof path: ${path}`);
  }
  return path;
}

async function load(path) {
  safePath(path);
  if (base) {
    const response = await fetch(base + path, { signal: AbortSignal.timeout(20_000) });
    if (!response.ok) throw new Error(`${path} returned ${response.status}`);
    return Buffer.from(await response.arrayBuffer());
  }
  return readFileSync(join(localRoot, path.slice(1)));
}

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

for (const artifact of manifest.artifacts ?? []) {
  const id = artifact?.id ?? "<missing id>";
  for (const kind of ["page", "json"]) {
    try {
      const path = safePath(artifact[kind]);
      const expected = artifact[`${kind}Sha256`];
      if (!/^[0-9a-f]{64}$/.test(expected ?? "")) {
        throw new Error(`${kind}Sha256 is missing or invalid`);
      }
      const actual = digest(await load(path));
      if (actual !== expected) {
        throw new Error(`${kind} hash mismatch: expected ${expected.slice(0, 12)}…, got ${actual.slice(0, 12)}…`);
      }
      console.log(`ok ${id} ${kind} sha256=${actual.slice(0, 12)}…`);
    } catch (error) {
      failures.push(`${id} ${kind}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
}

if (failures.length) {
  for (const failure of failures) console.error(`FAIL ${failure}`);
  process.exit(1);
}
console.log(`proof manifest ok (${manifest.artifacts.length} artifacts)`);
