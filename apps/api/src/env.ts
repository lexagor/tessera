import { z } from "zod";

import { productionConfigProblems } from "./production-config.js";

const bool = z
  .string()
  .optional()
  .transform((value) => value === "1" || value === "true" || value === "yes");

const schema = z.object({
  NODE_ENV: z.string().default("development"),
  API_PORT: z.coerce.number().default(8788),
  DATABASE_URL: z.string().min(1),
  BROKER_URL: z.string().url().default("http://localhost:8787"),
  REDIS_URL: z.string().url().optional(),
  BROKER_ADMIN_TOKEN: z.string().optional(),
  BROKER_ADMIN_KEY: z.string().optional(),
  BROKER_DEMO_ALLOW: bool,
  PUBLIC_BASE_URL: z.string().default("http://localhost:5173"),
  EVIDENCE_DIR: z.string().default("./data/evidence"),
  EVIDENCE_S3_BUCKET: z.preprocess(
    (value) => (value === "" ? undefined : value),
    z.string().optional(),
  ),
  EVIDENCE_S3_REGION: z.string().default("us-east-1"),
  EVIDENCE_S3_ENDPOINT: z.preprocess(
    (value) => (value === "" ? undefined : value),
    z.string().url().optional(),
  ),
  EVIDENCE_S3_ACCESS_KEY: z.preprocess(
    (value) => (value === "" ? undefined : value),
    z.string().optional(),
  ),
  EVIDENCE_S3_SECRET_KEY: z.preprocess(
    (value) => (value === "" ? undefined : value),
    z.string().optional(),
  ),
  EVIDENCE_S3_PREFIX: z.string().default("evidence"),
  EVIDENCE_S3_FORCE_PATH_STYLE: bool,
  CONTROL_PLANE_RLS: bool,
  TRUST_PROXY: bool,
  MAX_REQUEST_BYTES: z.coerce.number().int().min(1_024).default(2_097_152),
  REQUEST_TIMEOUT_MS: z.coerce.number().int().min(1_000).default(60_000),
  RATE_LIMIT_AUTH_PER_MINUTE: z.coerce.number().int().min(1).default(20),
  RATE_LIMIT_PUBLIC_PER_MINUTE: z.coerce.number().int().min(1).default(60),
  RATE_LIMIT_WRITE_PER_MINUTE: z.coerce.number().int().min(1).default(120),
  RATE_LIMIT_SCIM_PER_MINUTE: z.coerce.number().int().min(1).default(120),
  WEBHOOK_RETENTION_DAYS: z.coerce.number().int().min(0).default(30),
  VERIFY_BASE_URL: z.string().optional(),
  SESSION_COOKIE_NAME: z.string().optional(),
  SESSION_TTL_DAYS: z.coerce.number().default(7),
  SESSION_IDLE_HOURS: z.coerce.number().default(24),
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
  AGENT_RECEIPT_TSA_URL: z.preprocess(
    (value) => (value === "" ? undefined : value),
    z.string().url().optional(),
  ),
  AUTH_DEV_MODE: bool,
  OIDC_ISSUER: z.string().optional(),
  OIDC_CLIENT_ID: z.string().optional(),
  OIDC_CLIENT_SECRET: z.string().optional(),
  OIDC_REDIRECT_URI: z.string().optional(),
  OIDC_LOGOUT_URL: z.preprocess(
    (value) => (value === "" ? undefined : value),
    z.string().url().optional(),
  ),
  OIDC_ALLOWED_DOMAINS: z.string().optional(),
  OIDC_ALLOWED_EMAILS: z.string().optional(),
  OIDC_UNVERIFIED_DEMO_EMAILS: z.string().optional(),
  OIDC_STATE_SECRET: z.preprocess(
    (value) => (value === "" ? undefined : value),
    z.string().min(32).optional(),
  ),
  OIDC_ALLOW_EMAIL_LINKING: bool,
  BOOTSTRAP_EMAIL: z.preprocess(
    (value) => (value === "" ? undefined : value),
    z.string().email().optional(),
  ),
  COOKIE_SECURE: z.string().optional(),
  ALLOW_PRIVATE_WEBHOOKS: bool,
  STRIPE_SECRET_KEY: z.string().optional(),
  STRIPE_WEBHOOK_SECRET: z.string().optional(),
  STRIPE_PRICE_TEAM: z.string().optional(),
  STRIPE_PRICE_GROWTH: z.string().optional(),
  STRIPE_PORTAL_RETURN_URL: z.string().optional(),
  EMAIL_PROVIDER: z.enum(["disabled", "resend"]).default("disabled"),
  EMAIL_API_KEY: z.preprocess(
    (value) => (value === "" ? undefined : value),
    z.string().optional(),
  ),
  EMAIL_FROM: z.preprocess(
    (value) => (value === "" ? undefined : value),
    z.string().optional(),
  ),
  EMAIL_REPLY_TO: z.preprocess(
    (value) => (value === "" ? undefined : value),
    z.string().email().optional(),
  ),
  EMAIL_APP_URL: z.preprocess(
    (value) => (value === "" ? undefined : value),
    z.string().url().optional(),
  ),
});

const validatedSchema = schema.superRefine((value, ctx) => {
  for (const problem of productionConfigProblems(value)) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: problem });
  }
});

export const env = validatedSchema.parse(process.env);

export const isProduction = env.NODE_ENV === "production";
export const devAuthEnabled = env.AUTH_DEV_MODE || (!isProduction && !env.OIDC_ISSUER);
export const verifyBaseUrl = (env.VERIFY_BASE_URL ?? env.PUBLIC_BASE_URL).replace(/\/$/, "");
export const cookieSecure = env.COOKIE_SECURE
  ? ["1", "true"].includes(env.COOKIE_SECURE.trim().toLowerCase())
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
