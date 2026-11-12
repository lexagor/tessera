import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createSign, generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

const databaseUrl = process.env.TEST_DATABASE_URL;
const evidenceDir = await mkdtemp(join(tmpdir(), "tessera-oidc-test-"));
const clientId = "tessera-oidc-test";
const clientSecret = "tessera-oidc-test-secret";
const keyId = "tessera-test-key";
const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const publicJwk = {
  ...publicKey.export({ format: "jwk" }),
  kid: keyId,
  use: "sig",
  alg: "RS256",
};
const codes = new Map<string, { nonce: string; email: string; sub: string }>();

function base64url(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function json(res: ServerResponse, status: number, body: unknown): void {
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(body));
}

const oidc = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  const url = new URL(req.url ?? "/", "http://localhost");
  if (url.pathname === "/.well-known/openid-configuration") {
    const issuer = `http://127.0.0.1:${(oidc.address() as { port: number }).port}`;
    return json(res, 200, {
      issuer,
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      userinfo_endpoint: `${issuer}/userinfo`,
      jwks_uri: `${issuer}/jwks`,
      response_types_supported: ["code"],
      response_modes_supported: ["query"],
      grant_types_supported: ["authorization_code"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
      scopes_supported: ["openid", "email", "profile"],
      claims_supported: ["sub", "email", "email_verified", "name"],
    });
  }
  if (url.pathname === "/jwks") return json(res, 200, { keys: [publicJwk] });
  if (url.pathname === "/userinfo") {
    return json(res, 200, { sub: "oidc-user", email: "alice@example.com", name: "Alice" });
  }
  if (url.pathname === "/token" && req.method === "POST") {
    let raw = "";
    for await (const chunk of req) raw += chunk;
    const form = new URLSearchParams(raw);
    const code = form.get("code") ?? "";
    const record = codes.get(code);
    if (!record) return json(res, 400, { error: "invalid_grant" });
    codes.delete(code);
    const issuer = `http://127.0.0.1:${(oidc.address() as { port: number }).port}`;
    const now = Math.floor(Date.now() / 1000);
    const header = base64url({ alg: "RS256", typ: "JWT", kid: keyId });
    const payload = base64url({
      iss: issuer,
      sub: record.sub,
      aud: clientId,
      email: record.email,
      email_verified: true,
      name: "Alice",
      nonce: record.nonce,
      iat: now,
      exp: now + 300,
    });
    const signer = createSign("RSA-SHA256");
    signer.update(`${header}.${payload}`);
    const signature = signer.sign(privateKey).toString("base64url");
    return json(res, 200, {
      access_token: randomBytes(16).toString("hex"),
      token_type: "Bearer",
      expires_in: 300,
      id_token: `${header}.${payload}.${signature}`,
    });
  }
  return json(res, 404, { error: `mock OIDC has no ${req.method} ${url.pathname}` });
});

const oidcPort = await new Promise<number>((resolve, reject) => {
  oidc.once("error", reject);
  oidc.listen(0, "127.0.0.1", () => {
    const address = oidc.address();
    if (!address || typeof address === "string") return reject(new Error("no OIDC port"));
    resolve(address.port);
  });
});
const issuer = `http://127.0.0.1:${oidcPort}`;
const redirectUri = "http://localhost:8788/auth/callback";

process.env.NODE_ENV = "test";
process.env.DATABASE_URL = databaseUrl ?? "postgres://unused";
process.env.AUTH_DEV_MODE = "0";
process.env.BROKER_DEMO_ALLOW = "1";
process.env.OIDC_ISSUER = issuer;
process.env.OIDC_CLIENT_ID = clientId;
process.env.OIDC_CLIENT_SECRET = clientSecret;
process.env.OIDC_REDIRECT_URI = redirectUri;
process.env.OIDC_ALLOWED_DOMAINS = "example.com";
process.env.PUBLIC_BASE_URL = "http://localhost:5173";
process.env.VERIFY_BASE_URL = "https://verify.thetessera.xyz";
process.env.CONTROL_PLANE_ENC_KEY = "11".repeat(32);
process.env.TESSERA_AUTHORITY_HMAC_SECRET = "tessera-test-authority-secret-32-bytes-minimum";
process.env.EVIDENCE_DIR = evidenceDir;

const canRun = Boolean(databaseUrl);

after(async () => {
  await new Promise<void>((resolve) => oidc.close(() => resolve()));
});

test("OIDC login creates a session and mints an OIDC-bound authority token", { skip: !canRun, timeout: 30_000 }, async () => {
  const { migrate, closeDb, db } = await import("../src/db.js");
  await migrate();
  const { app } = await import("../src/index.js");
  const { verifyAuthorityToken } = await import("../src/authority.js");

  const login = await app.request("/auth/login", { redirect: "manual" });
  assert.equal(login.status, 302);
  const location = login.headers.get("location");
  assert.ok(location);
  const authorizeUrl = new URL(location);
  const state = authorizeUrl.searchParams.get("state");
  const nonce = authorizeUrl.searchParams.get("nonce");
  assert.ok(state);
  assert.ok(nonce);
  const cookie = login.headers.get("set-cookie")?.split(";")[0];
  assert.ok(cookie?.startsWith("tessera_oidc="));

  const code = randomBytes(12).toString("hex");
  const sub = `oidc-${Date.now()}`;
  codes.set(code, { nonce, email: "alice@example.com", sub });

  const callback = await app.request(
    `${redirectUri}?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`,
    { redirect: "manual", headers: { cookie } },
  );
  assert.equal(callback.status, 302);
  const sessionCookie = callback.headers
    .getSetCookie()
    .find((value) => value.startsWith("tessera_session="))
    ?.split(";")[0];
  assert.ok(sessionCookie?.startsWith("tessera_session="));
  const auth = { cookie: sessionCookie! };

  const session = await app.request("/v1/session", { headers: auth });
  assert.equal(session.status, 200);
  const sessionBody = (await session.json()) as {
    user: { id: string; email: string; oidc_subject: string | null };
    org: { id: string };
  };
  assert.equal(sessionBody.user.email, "alice@example.com");
  assert.equal(sessionBody.user.oidc_subject, sub);

  const environmentResponse = await app.request("/v1/environments", {
    method: "POST",
    headers: { ...auth, "content-type": "application/json" },
    body: JSON.stringify({ name: "OIDC Test" }),
  });
  assert.equal(environmentResponse.status, 201);
  const environment = (await environmentResponse.json()) as { id: string };

  const tokenResponse = await app.request(
    `/v1/authority-tokens?environmentId=${encodeURIComponent(environment.id)}`,
    {
      method: "POST",
      headers: { ...auth, "content-type": "application/json" },
      body: JSON.stringify({ agentId: "oidc-agent", ttlSeconds: 60 }),
    },
  );
  assert.equal(tokenResponse.status, 200);
  const minted = (await tokenResponse.json()) as { token: string };
  const claims = verifyAuthorityToken(minted.token, {
    orgId: sessionBody.org.id,
    environmentId: environment.id,
    agentId: "oidc-agent",
  });
  assert.equal(claims.sub, sessionBody.user.id);
  assert.equal(claims.authority_ref, `oidc:${sub}`);

  await db()`DELETE FROM orgs WHERE id = ${sessionBody.org.id}`;
  await closeDb();
});
