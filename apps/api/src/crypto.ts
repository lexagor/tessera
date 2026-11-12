import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  randomUUID,
} from "node:crypto";

import { env } from "./env.js";

export function uuid(): string {
  return randomUUID();
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

export function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function keyPrefix(key: string): string {
  return key.slice(0, 12);
}

export function newAgentKey(): { key: string; prefix: string; hash: string } {
  const key = `tsk_live_${randomToken(24)}`;
  return { key, prefix: keyPrefix(key), hash: sha256(key) };
}

export function slugify(value: string): string {
  const slug = value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
  return slug || "org";
}

function encryptionKey(): Buffer {
  const raw = env.CONTROL_PLANE_ENC_KEY;
  if (!raw) {
    throw new Error("CONTROL_PLANE_ENC_KEY is required for persisted broker credentials");
  }
  const key = Buffer.from(raw.replace(/^0x/, ""), "hex");
  if (key.length !== 32) {
    throw new Error("CONTROL_PLANE_ENC_KEY must be a 32-byte hex value");
  }
  return key;
}

/** AES-256-GCM envelope for broker credentials stored in the control-plane DB. */
export function encryptSecret(plaintext: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1:${iv.toString("base64url")}:${tag.toString("base64url")}:${ciphertext.toString("base64url")}`;
}

export function decryptSecret(stored: string): string {
  const [, iv, tag, ciphertext] = stored.split(":");
  if (!iv || !tag || !ciphertext) throw new Error("invalid encrypted secret");
  const decipher = createDecipheriv(
    "aes-256-gcm",
    encryptionKey(),
    Buffer.from(iv, "base64url"),
  );
  decipher.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(ciphertext, "base64url")),
    decipher.final(),
  ]).toString("utf8");
}
