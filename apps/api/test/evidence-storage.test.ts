import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

process.env.NODE_ENV = "test";
process.env.DATABASE_URL = process.env.DATABASE_URL ?? "postgres://unused";
const root = await mkdtemp(join(tmpdir(), "tessera-evidence-storage-"));
process.env.EVIDENCE_DIR = root;

const { LocalEvidenceStorage, signS3Request } = await import("../src/evidence-storage.js");

after(async () => {
  await rm(root, { recursive: true, force: true });
});

test("local evidence storage writes and reads within EVIDENCE_DIR", async () => {
  const storage = new LocalEvidenceStorage();
  const locator = await storage.put("pack-1.tar.gz", new Uint8Array([1, 2, 3]));
  assert.equal(locator, join(root, "pack-1.tar.gz"));
  assert.deepEqual([...await storage.get(locator)], [1, 2, 3]);
  await storage.delete(locator);
});

test("local evidence storage rejects traversal and outside locators", async () => {
  const storage = new LocalEvidenceStorage();
  await assert.rejects(() => storage.put("../escape.tar.gz", new Uint8Array([1])), /invalid evidence/);
  await assert.rejects(() => storage.get("/etc/passwd"), /outside EVIDENCE_DIR/);
});

test("S3 signing produces a path-style SigV4 request without exposing the secret", () => {
  const signed = signS3Request({
    method: "PUT",
    endpoint: "https://s3.example.test",
    bucket: "tessera-evidence",
    key: "evidence/pack 1.tar.gz",
    region: "us-east-1",
    accessKey: "AKIATEST",
    secretKey: "secret-value",
    body: new Uint8Array([1, 2, 3]),
    forcePathStyle: true,
    now: new Date("2026-11-13T06:00:00Z"),
  });
  assert.match(signed.url, /^https:\/\/s3\.example\.test\/tessera-evidence\/evidence\/pack%201\.tar\.gz$/);
  assert.match(signed.headers.authorization, /^AWS4-HMAC-SHA256 Credential=AKIATEST\/20261113\/us-east-1\/s3\/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=[0-9a-f]{64}$/);
  assert.equal(signed.headers["x-amz-date"], "20261113T060000Z");
  assert.equal(signed.headers["x-amz-content-sha256"], "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81");
  assert.ok(!JSON.stringify(signed).includes("secret-value"));
});
