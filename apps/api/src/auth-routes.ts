import { Hono } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { generators, Issuer, type Client } from "openid-client";

import {
  OIDC_COOKIE,
  type AppEnv,
  clearSessionCookie,
  createSession,
  destroySession,
  findMembership,
  oidcCookieOptions,
  requireSession,
  setSessionCookie,
  upsertOidcUser,
} from "./auth.js";
import { db } from "./db.js";
import { devAuthEnabled, env, requireOidcConfig } from "./env.js";

export const authRoutes = new Hono<AppEnv>();

let oidcClient: Client | null = null;

async function getOidcClient(): Promise<Client> {
  if (oidcClient) return oidcClient;
  const config = requireOidcConfig();
  const issuer = await Issuer.discover(config.issuer);
  oidcClient = new issuer.Client({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    redirect_uris: [config.redirectUri],
    response_types: ["code"],
  });
  return oidcClient;
}

authRoutes.get("/auth/config", (c) =>
  c.json({ devAuth: devAuthEnabled, oidc: Boolean(env.OIDC_ISSUER) }),
);

authRoutes.get("/auth/login", async (c) => {
  if (devAuthEnabled && !env.OIDC_ISSUER) {
    return c.redirect("/auth/dev-login");
  }
  const client = await getOidcClient();
  const state = generators.state();
  const nonce = generators.nonce();
  const verifier = generators.codeVerifier();
  const challenge = generators.codeChallenge(verifier);
  const url = client.authorizationUrl({
    scope: "openid email profile",
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  setCookie(
    c,
    OIDC_COOKIE,
    Buffer.from(JSON.stringify({ state, nonce, verifier })).toString("base64url"),
    oidcCookieOptions(),
  );
  return c.redirect(url);
});

authRoutes.get("/auth/dev-login", async (c) => {
  if (!devAuthEnabled) return c.json({ error: "dev auth is disabled" }, 404);
  const user = await upsertOidcUser({
    email: "dev@tessera.local",
    name: "Dev User",
    subject: "dev",
  });
  const membership = await findMembership(user.id);
  const session = await createSession(user.id, membership?.org.id ?? null);
  setSessionCookie(c, session.token);
  return c.redirect(env.PUBLIC_BASE_URL);
});

authRoutes.get("/auth/callback", async (c) => {
  const config = requireOidcConfig();
  const client = await getOidcClient();
  const raw = getCookie(c, OIDC_COOKIE);
  if (!raw) return c.json({ error: "missing OIDC state" }, 400);
  deleteCookie(c, OIDC_COOKIE, { path: "/" });
  let stored: { state: string; nonce: string; verifier: string };
  try {
    stored = JSON.parse(Buffer.from(raw, "base64url").toString("utf8"));
  } catch {
    return c.json({ error: "invalid OIDC state" }, 400);
  }
  const params = client.callbackParams(c.req.url);
  const tokenSet = await client.callback(config.redirectUri, params, {
    state: stored.state,
    nonce: stored.nonce,
    code_verifier: stored.verifier,
  });
  let claims = tokenSet.claims();
  if (!claims.email) {
    const userinfo = await client.userinfo(tokenSet);
    claims = { ...claims, ...userinfo };
  }
  const email = typeof claims.email === "string" ? claims.email.toLowerCase() : null;
  if (!email) return c.json({ error: "OIDC response has no email" }, 400);
  const allowedDomains = (env.OIDC_ALLOWED_DOMAINS ?? "")
    .split(",")
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);
  const invite = await db()`
    SELECT 1 FROM invites
     WHERE lower(email) = ${email} AND accepted_at IS NULL AND expires_at > now()
     LIMIT 1
  `;
  const domainAllowed =
    allowedDomains.length > 0 &&
    allowedDomains.some((domain) => email.endsWith(`@${domain}`));
  const bootstrapAllowed = env.BOOTSTRAP_EMAIL?.toLowerCase() === email;
  if (invite.length === 0 && !domainAllowed && !bootstrapAllowed) {
    return c.json({ error: "This email is not invited to this workspace" }, 403);
  }
  const user = await upsertOidcUser({
    email,
    name: typeof claims.name === "string" ? claims.name : null,
    subject: typeof claims.sub === "string" ? claims.sub : null,
  });
  const membership = await findMembership(user.id);
  const session = await createSession(user.id, membership?.org.id ?? null);
  setSessionCookie(c, session.token);
  return c.redirect(env.PUBLIC_BASE_URL);
});

authRoutes.post("/auth/logout", requireSession, async (c) => {
  await destroySession(c);
  clearSessionCookie(c);
  return c.json({ ok: true });
});
