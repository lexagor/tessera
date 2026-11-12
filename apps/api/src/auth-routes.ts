import { Hono } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { generators, Issuer, type Client } from "openid-client";

import {
  OidcIdentityConflict,
  type AppEnv,
  clearSessionCookie,
  createSession,
  destroySession,
  findMembership,
  findOidcUser,
  oidcCookieName,
  oidcCookieOptions,
  requireSession,
  setSessionCookie,
  upsertOidcUser,
} from "./auth.js";
import { clientIp } from "./client-ip.js";
import { trustedWriteOrigin } from "./csrf.js";
import { db } from "./db.js";
import { cookieSecure, devAuthEnabled, env, isProduction, requireOidcConfig } from "./env.js";
import { decodeOidcState, encodeOidcState } from "./oidc-state.js";
import { rateLimit } from "./rate-limit.js";

export const authRoutes = new Hono<AppEnv>();

const authRateLimit = rateLimit({
  name: "auth",
  limit: env.RATE_LIMIT_AUTH_PER_MINUTE,
  key: (c) => `auth:${clientIp(c)}`,
});
authRoutes.use("/auth/login", authRateLimit);
authRoutes.use("/auth/callback", authRateLimit);
authRoutes.use("/auth/dev-login", authRateLimit);

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
    oidcCookieName(),
    encodeOidcState({ state, nonce, verifier }),
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
  const raw = getCookie(c, oidcCookieName());
  if (!raw) return c.json({ error: "missing OIDC state" }, 400);
  deleteCookie(c, oidcCookieName(), { path: "/", secure: cookieSecure });
  const stored = decodeOidcState(raw);
  if (!stored) return c.json({ error: "invalid OIDC state" }, 400);
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
  const subject = typeof claims.sub === "string" ? claims.sub : null;
  if (!subject) return c.json({ error: "OIDC response has no subject" }, 400);
  const emailVerified = claims.email_verified === true;
  if (isProduction && !emailVerified) {
    return c.json({ error: "OIDC email must be verified" }, 403);
  }
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
  const existing = await findOidcUser({ issuer: config.issuer, subject });
  let bootstrapAllowed = false;
  if (!existing && env.BOOTSTRAP_EMAIL?.toLowerCase() === email) {
    const users = await db()`SELECT 1 FROM users LIMIT 1`;
    bootstrapAllowed = users.length === 0;
  }
  if (!existing && invite.length === 0 && !domainAllowed && !bootstrapAllowed) {
    return c.json({ error: "This email is not invited to this workspace" }, 403);
  }
  let user: Awaited<ReturnType<typeof upsertOidcUser>>;
  try {
    user = await upsertOidcUser({
      email,
      name: typeof claims.name === "string" ? claims.name : null,
      issuer: config.issuer,
      subject,
      emailVerified,
    });
  } catch (error) {
    if (error instanceof OidcIdentityConflict) {
      return c.json({ error: error.message }, 409);
    }
    throw error;
  }
  const membership = await findMembership(user.id);
  const session = await createSession(user.id, membership?.org.id ?? null);
  setSessionCookie(c, session.token);
  return c.redirect(env.PUBLIC_BASE_URL);
});

authRoutes.post("/auth/logout", requireSession, async (c) => {
  if (!trustedWriteOrigin(c.req.header("origin"))) {
    return c.json({ error: "Cross-origin write rejected" }, 403);
  }
  await destroySession(c);
  clearSessionCookie(c);
  return c.json({ ok: true });
});
