import { z } from "zod";

const bool = z
  .string()
  .optional()
  .transform((value) => value === "1" || value === "true" || value === "yes");

const schema = z.object({
  NODE_ENV: z.string().default("development"),
  API_PORT: z.coerce.number().default(8788),
  DATABASE_URL: z.string().min(1),
  BROKER_URL: z.string().url().default("http://localhost:8787"),
  BROKER_ADMIN_TOKEN: z.string().optional(),
  BROKER_ADMIN_KEY: z.string().optional(),
  BROKER_DEMO_ALLOW: bool,
  PUBLIC_BASE_URL: z.string().default("http://localhost:5173"),
  EVIDENCE_DIR: z.string().default("./data/evidence"),
  VERIFY_BASE_URL: z.string().optional(),
  SESSION_COOKIE_NAME: z.string().default("tessera_session"),
  SESSION_TTL_DAYS: z.coerce.number().default(7),
  TESSERA_AUTHORITY_HMAC_SECRET: z.preprocess(
    (value) => (value === "" ? undefined : value),
    z.string().min(32).optional(),
  ),
  TESSERA_AUTHORITY_HMAC_SECRET_PREVIOUS: z.preprocess(
    (value) => (value === "" ? undefined : value),
    z.string().min(32).optional(),
  ),
  TESSERA_AUTHORITY_KID: z.string().min(1).max(64).default("v1"),
  TESSERA_AUTHORITY_PREVIOUS_KID: z.string().min(1).max(64).default("v0"),
  TESSERA_AUTHORITY_ISSUER: z.string().min(1).max(256).default("tessera-api"),
  TESSERA_AUTHORITY_AUDIENCE: z.string().min(1).max(256).default("tessera-broker"),
  TESSERA_AUTHORITY_TOKEN_TTL_SECONDS: z.coerce.number().int().min(30).max(86_400).default(300),
  TESSERA_AUTHORITY_MINT_PER_MINUTE: z.coerce.number().int().min(1).max(600).default(30),
  CONTROL_PLANE_ENC_KEY: z.string().optional(),
  AGENT_RECEIPT_ED25519_KEY: z.string().optional(),
  AGENT_RECEIPT_ISSUER_DID: z.string().optional(),
  AGENT_RECEIPT_TSA_URL: z.string().url().optional(),
  AUTH_DEV_MODE: bool,
  OIDC_ISSUER: z.string().optional(),
  OIDC_CLIENT_ID: z.string().optional(),
  OIDC_CLIENT_SECRET: z.string().optional(),
  OIDC_REDIRECT_URI: z.string().optional(),
  OIDC_ALLOWED_DOMAINS: z.string().optional(),
  BOOTSTRAP_EMAIL: z.string().email().optional(),
  COOKIE_SECURE: z.string().optional(),
  ALLOW_PRIVATE_WEBHOOKS: bool,
  STRIPE_SECRET_KEY: z.string().optional(),
  STRIPE_WEBHOOK_SECRET: z.string().optional(),
  STRIPE_PRICE_TEAM: z.string().optional(),
  STRIPE_PRICE_GROWTH: z.string().optional(),
  STRIPE_PORTAL_RETURN_URL: z.string().optional(),
});

export const env = schema.parse(process.env);

export const isProduction = env.NODE_ENV === "production";
export const devAuthEnabled = env.AUTH_DEV_MODE || (!isProduction && !env.OIDC_ISSUER);
export const verifyBaseUrl = (env.VERIFY_BASE_URL ?? env.PUBLIC_BASE_URL).replace(/\/$/, "");
export const cookieSecure = env.COOKIE_SECURE
  ? env.COOKIE_SECURE === "1" || env.COOKIE_SECURE === "true"
  : isProduction;

export function requireOidcConfig() {
  const missing = [
    ["OIDC_ISSUER", env.OIDC_ISSUER],
    ["OIDC_CLIENT_ID", env.OIDC_CLIENT_ID],
    ["OIDC_CLIENT_SECRET", env.OIDC_CLIENT_SECRET],
    ["OIDC_REDIRECT_URI", env.OIDC_REDIRECT_URI],
  ]
    .filter(([, value]) => !value)
    .map(([name]) => name);
  if (missing.length > 0) {
    throw new Error(`OIDC is not configured: missing ${missing.join(", ")}`);
  }
  return {
    issuer: env.OIDC_ISSUER!,
    clientId: env.OIDC_CLIENT_ID!,
    clientSecret: env.OIDC_CLIENT_SECRET!,
    redirectUri: env.OIDC_REDIRECT_URI!,
  };
}
