import { createHash, createHmac } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, resolve, sep } from "node:path";

import { env } from "./env.js";

export interface EvidenceStorage {
  readonly kind: "local" | "s3";
  put(key: string, data: Uint8Array): Promise<string>;
  get(locator: string): Promise<Uint8Array>;
  delete(locator: string): Promise<void>;
}

const LOCATOR_PREFIX = "s3://";

export function s3EvidenceConfigured(): boolean {
  return Boolean(
    env.EVIDENCE_S3_BUCKET &&
      env.EVIDENCE_S3_ACCESS_KEY &&
      env.EVIDENCE_S3_SECRET_KEY,
  );
}

function localRoot(): string {
  return resolve(env.EVIDENCE_DIR);
}

function safeLocalPath(locator: string): string {
  const root = localRoot();
  const path = resolve(locator);
  if (path !== root && !path.startsWith(`${root}${sep}`)) {
    throw new Error("evidence object is outside EVIDENCE_DIR");
  }
  return path;
}

function safeObjectKey(key: string): string {
  const clean = key.replace(/^\/+/, "");
  if (!clean || clean.split("/").some((part) => part === ".." || part === ".")) {
    throw new Error("invalid evidence object key");
  }
  return clean;
}

export class LocalEvidenceStorage implements EvidenceStorage {
  readonly kind = "local" as const;

  async put(key: string, data: Uint8Array): Promise<string> {
    const path = resolve(localRoot(), safeObjectKey(key));
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, data);
    return path;
  }

  async get(locator: string): Promise<Uint8Array> {
    return new Uint8Array(await readFile(safeLocalPath(locator)));
  }

  async delete(locator: string): Promise<void> {
    await rm(safeLocalPath(locator), { force: true });
  }
}

export interface S3RequestInput {
  method: "GET" | "PUT" | "DELETE";
  endpoint: string;
  bucket: string;
  key: string;
  region: string;
  accessKey: string;
  secretKey: string;
  body?: Uint8Array;
  forcePathStyle?: boolean;
  now?: Date;
}

export interface SignedS3Request {
  url: string;
  headers: Record<string, string>;
}

function awsUriEncode(value: string): string {
  return encodeURIComponent(value)
    .replace(/[!'()*]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`)
    .replace(/%2F/g, "/");
}

function sha256Hex(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

function hmac(key: Buffer | string, value: string): Buffer {
  return createHmac("sha256", key).update(value).digest();
}

/** SigV4 for the small subset of S3 operations Tessera needs (no query parameters). */
export function signS3Request(input: S3RequestInput): SignedS3Request {
  const endpoint = new URL(input.endpoint);
  const key = safeObjectKey(input.key);
  const pathStyle = input.forcePathStyle ?? endpoint.hostname.endsWith(".amazonaws.com") === false;
  const canonicalUri = pathStyle
    ? `${endpoint.pathname.replace(/\/$/, "")}/${awsUriEncode(input.bucket)}/${awsUriEncode(key)}`
    : `${endpoint.pathname.replace(/\/$/, "")}/${awsUriEncode(key)}`;
  const host = endpoint.host;
  const now = input.now ?? new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const shortDate = amzDate.slice(0, 8);
  const payloadHash = sha256Hex(input.body ?? new Uint8Array());
  const canonicalHeaders = `host:${host}\nx-amz-content-sha256:${payloadHash}\nx-amz-date:${amzDate}\n`;
  const signedHeaders = "host;x-amz-content-sha256;x-amz-date";
  const canonicalRequest = [
    input.method,
    canonicalUri,
    "",
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");
  const scope = `${shortDate}/${input.region}/s3/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    scope,
    sha256Hex(canonicalRequest),
  ].join("\n");
  const signingKey = hmac(
    hmac(hmac(hmac(`AWS4${input.secretKey}`, shortDate), input.region), "s3"),
    "aws4_request",
  );
  const signature = createHmac("sha256", signingKey).update(stringToSign).digest("hex");
  const authorization = `AWS4-HMAC-SHA256 Credential=${input.accessKey}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return {
    url: `${endpoint.origin}${canonicalUri}`,
    headers: {
      authorization,
      "x-amz-content-sha256": payloadHash,
      "x-amz-date": amzDate,
      "content-type": "application/gzip",
    },
  };
}

export class S3EvidenceStorage implements EvidenceStorage {
  readonly kind = "s3" as const;

  constructor(
    private readonly config: {
      bucket: string;
      region: string;
      endpoint: string;
      accessKey: string;
      secretKey: string;
      prefix: string;
      forcePathStyle: boolean;
    },
  ) {}

  private objectKey(key: string): string {
    return safeObjectKey(`${this.config.prefix.replace(/^\/+|\/+$/g, "")}/${safeObjectKey(key)}`);
  }

  private async request(
    method: "GET" | "PUT" | "DELETE",
    key: string,
    body?: Uint8Array,
  ): Promise<Response> {
    const signed = signS3Request({
      method,
      endpoint: this.config.endpoint,
      bucket: this.config.bucket,
      key,
      region: this.config.region,
      accessKey: this.config.accessKey,
      secretKey: this.config.secretKey,
      body,
      forcePathStyle: this.config.forcePathStyle,
    });
    const response = await fetch(signed.url, {
      method,
      headers: signed.headers,
      body: body ? Buffer.from(body) : undefined,
      redirect: "error",
      signal: AbortSignal.timeout(60_000),
    });
    if (!response.ok) {
      const detail = await response.text().catch(() => "");
      throw new Error(`S3 ${method} failed (${response.status})${detail ? `: ${detail.slice(0, 200)}` : ""}`);
    }
    return response;
  }

  async put(key: string, data: Uint8Array): Promise<string> {
    const objectKey = this.objectKey(key);
    await this.request("PUT", objectKey, data);
    return `${LOCATOR_PREFIX}${this.config.bucket}/${objectKey}`;
  }

  async get(locator: string): Promise<Uint8Array> {
    if (!locator.startsWith(LOCATOR_PREFIX)) {
      return new LocalEvidenceStorage().get(locator);
    }
    const key = this.locatorKey(locator);
    const response = await this.request("GET", key);
    return new Uint8Array(await response.arrayBuffer());
  }

  async delete(locator: string): Promise<void> {
    if (!locator.startsWith(LOCATOR_PREFIX)) {
      return new LocalEvidenceStorage().delete(locator);
    }
    await this.request("DELETE", this.locatorKey(locator));
  }

  private locatorKey(locator: string): string {
    if (!locator.startsWith(LOCATOR_PREFIX)) throw new Error("invalid S3 evidence locator");
    const rest = locator.slice(LOCATOR_PREFIX.length);
    const slash = rest.indexOf("/");
    if (slash <= 0) throw new Error("invalid S3 evidence locator");
    const bucket = rest.slice(0, slash);
    if (bucket !== this.config.bucket) throw new Error("evidence locator belongs to another bucket");
    return safeObjectKey(rest.slice(slash + 1));
  }
}

let singleton: EvidenceStorage | null = null;

export function evidenceStorage(): EvidenceStorage {
  if (singleton) return singleton;
  if (s3EvidenceConfigured()) {
    singleton = new S3EvidenceStorage({
      bucket: env.EVIDENCE_S3_BUCKET!,
      region: env.EVIDENCE_S3_REGION,
      endpoint:
        env.EVIDENCE_S3_ENDPOINT ??
        `https://${env.EVIDENCE_S3_BUCKET}.s3.${env.EVIDENCE_S3_REGION}.amazonaws.com`,
      accessKey: env.EVIDENCE_S3_ACCESS_KEY!,
      secretKey: env.EVIDENCE_S3_SECRET_KEY!,
      prefix: env.EVIDENCE_S3_PREFIX,
      forcePathStyle: env.EVIDENCE_S3_FORCE_PATH_STYLE,
    });
  } else {
    singleton = new LocalEvidenceStorage();
  }
  return singleton;
}

export function resetEvidenceStorageForTests(): void {
  singleton = null;
}
