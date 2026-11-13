export interface ProductionConfigInput {
  NODE_ENV: string;
  PUBLIC_BASE_URL: string;
  VERIFY_BASE_URL?: string;
  OIDC_ISSUER?: string;
  OIDC_CLIENT_ID?: string;
  OIDC_CLIENT_SECRET?: string;
  OIDC_REDIRECT_URI?: string;
  OIDC_STATE_SECRET?: string;
  AUTH_DEV_MODE: boolean;
  COOKIE_SECURE?: string;
  ALLOW_PRIVATE_WEBHOOKS: boolean;
  BROKER_DEMO_ALLOW: boolean;
  CONTROL_PLANE_ENC_KEY?: string;
  TESSERA_AUTHORITY_HMAC_SECRET?: string;
  SESSION_COOKIE_NAME?: string;
  BROKER_ADMIN_KEY?: string;
  BROKER_ADMIN_TOKEN?: string;
  EMAIL_PROVIDER?: string;
  EMAIL_API_KEY?: string;
  EMAIL_FROM?: string;
  EVIDENCE_S3_BUCKET?: string;
  EVIDENCE_S3_ACCESS_KEY?: string;
  EVIDENCE_S3_SECRET_KEY?: string;
}

const DEV_SECRETS = new Set([
  "tessera-dev-authority-secret-32-bytes-minimum",
  "tessera-dev-oidc-state-secret-32-bytes-minimum",
  "0x2222222222222222222222222222222222222222222222222222222222222222",
  "2222222222222222222222222222222222222222222222222222222222222222",
  "0x1111111111111111111111111111111111111111111111111111111111111111",
  "1111111111111111111111111111111111111111111111111111111111111111",
  "dev-admin-token",
]);

function httpsUrl(value: string | undefined): boolean {
  if (!value) return false;
  try {
    return new URL(value).protocol === "https:";
  } catch {
    return false;
  }
}

function hex32(value: string | undefined): boolean {
  return Boolean(value && /^(0x)?[0-9a-fA-F]{64}$/.test(value));
}

function isDevSecret(value: string | undefined): boolean {
  return value ? DEV_SECRETS.has(value.trim().toLowerCase()) : false;
}

/** Problems that must block a production boot. Kept pure so it can be unit-tested. */
export function productionConfigProblems(config: ProductionConfigInput): string[] {
  if (config.NODE_ENV !== "production") return [];
  const problems: string[] = [];

  if (!httpsUrl(config.PUBLIC_BASE_URL)) {
    problems.push("PUBLIC_BASE_URL must be an https URL in production");
  }
  if (config.VERIFY_BASE_URL && !httpsUrl(config.VERIFY_BASE_URL)) {
    problems.push("VERIFY_BASE_URL must be an https URL in production");
  }
  if (!httpsUrl(config.OIDC_ISSUER)) {
    problems.push("OIDC_ISSUER must be an https URL in production");
  }
  for (const name of ["OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_REDIRECT_URI"] as const) {
    if (!config[name]) problems.push(`${name} is required in production`);
  }
  if (config.OIDC_REDIRECT_URI && !httpsUrl(config.OIDC_REDIRECT_URI)) {
    problems.push("OIDC_REDIRECT_URI must be an https URL in production");
  }
  if (!config.OIDC_STATE_SECRET || config.OIDC_STATE_SECRET.length < 32) {
    problems.push("OIDC_STATE_SECRET must be at least 32 bytes in production");
  } else if (isDevSecret(config.OIDC_STATE_SECRET)) {
    problems.push("OIDC_STATE_SECRET must not use a development default");
  }

  if (config.AUTH_DEV_MODE) problems.push("AUTH_DEV_MODE must be disabled in production");
  const secureCookie = config.COOKIE_SECURE?.trim().toLowerCase();
  if (secureCookie !== "1" && secureCookie !== "true") {
    problems.push("COOKIE_SECURE must be enabled in production");
  }
  if (config.ALLOW_PRIVATE_WEBHOOKS) {
    problems.push("ALLOW_PRIVATE_WEBHOOKS must be disabled in production");
  }
  if (config.BROKER_DEMO_ALLOW) {
    problems.push("BROKER_DEMO_ALLOW must be disabled in production");
  }

  if (!hex32(config.CONTROL_PLANE_ENC_KEY)) {
    problems.push("CONTROL_PLANE_ENC_KEY must be a 32-byte hex value in production");
  } else if (isDevSecret(config.CONTROL_PLANE_ENC_KEY)) {
    problems.push("CONTROL_PLANE_ENC_KEY must not use a development default");
  }
  if (!config.TESSERA_AUTHORITY_HMAC_SECRET || config.TESSERA_AUTHORITY_HMAC_SECRET.length < 32) {
    problems.push("TESSERA_AUTHORITY_HMAC_SECRET must be at least 32 bytes in production");
  } else if (isDevSecret(config.TESSERA_AUTHORITY_HMAC_SECRET)) {
    problems.push("TESSERA_AUTHORITY_HMAC_SECRET must not use a development default");
  }
  if (!config.BROKER_ADMIN_KEY) {
    problems.push("BROKER_ADMIN_KEY is required in production");
  } else if (isDevSecret(config.BROKER_ADMIN_KEY)) {
    problems.push("BROKER_ADMIN_KEY must not use a development default");
  }
  if (!config.BROKER_ADMIN_TOKEN) {
    problems.push("BROKER_ADMIN_TOKEN is required in production");
  } else if (isDevSecret(config.BROKER_ADMIN_TOKEN)) {
    problems.push("BROKER_ADMIN_TOKEN must not use a development default");
  }
  if (config.SESSION_COOKIE_NAME && !config.SESSION_COOKIE_NAME.startsWith("__Host-")) {
    problems.push("SESSION_COOKIE_NAME must use the __Host- prefix in production");
  }
  if (config.EMAIL_PROVIDER && config.EMAIL_PROVIDER !== "disabled") {
    if (config.EMAIL_PROVIDER !== "resend") {
      problems.push("EMAIL_PROVIDER must be disabled or resend");
    }
    if (!config.EMAIL_API_KEY) problems.push("EMAIL_API_KEY is required when EMAIL_PROVIDER is enabled");
    if (!config.EMAIL_FROM) problems.push("EMAIL_FROM is required when EMAIL_PROVIDER is enabled");
  }
  if (config.EVIDENCE_S3_BUCKET) {
    if (!config.EVIDENCE_S3_ACCESS_KEY || !config.EVIDENCE_S3_SECRET_KEY) {
      problems.push("EVIDENCE_S3_ACCESS_KEY and EVIDENCE_S3_SECRET_KEY are required when EVIDENCE_S3_BUCKET is set");
    }
  }

  return problems;
}
