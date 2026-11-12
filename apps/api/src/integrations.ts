import { persistAction, persistOutcome } from "./actions.js";
import { audit } from "./audit.js";
import * as broker from "./broker.js";
import { decryptSecret, encryptSecret, sha256, uuid } from "./crypto.js";
import { db } from "./db.js";
import { env } from "./env.js";
import type { Environment } from "./types.js";

export type IntegrationStatus = "connected" | "needs_attention" | "disabled";
export type IntegrationAuthMode = "broker_managed" | "api_key" | "basic" | "sdk";

export interface IntegrationCredentialField {
  key: string;
  label: string;
  placeholder?: string;
  secret?: boolean;
  required?: boolean;
  help?: string;
}

export interface IntegrationScope {
  id: string;
  label: string;
  resource: string;
  description: string;
  risk: "low" | "medium" | "high";
}

export interface IntegrationProvider {
  id: string;
  name: string;
  category: string;
  description: string;
  authMode: IntegrationAuthMode;
  credentialFields: IntegrationCredentialField[];
  scopes: IntegrationScope[];
  sample: {
    tool: string;
    args: Record<string, unknown>;
    intent: string;
  };
  docsUrl: string;
  maturity: "ga" | "preview" | "sdk";
  color: string;
}

export interface IntegrationView {
  id: string;
  provider: string;
  providerName: string;
  providerCategory: string;
  name: string;
  status: IntegrationStatus;
  authMode: IntegrationAuthMode;
  scopes: IntegrationScope[];
  owner: { id: string; email: string; name: string | null } | null;
  environment: { id: string; name: string };
  hasCredential: boolean;
  credentialHint: string | null;
  metadata: Record<string, unknown>;
  policyId: string | null;
  testActionId: string | null;
  lastSyncAt: string | null;
  lastTestedAt: string | null;
  lastTestOk: boolean | null;
  lastTestMessage: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface ProbeResult {
  ok: boolean;
  mode: "broker_managed" | "api_key" | "basic" | "sdk" | "configuration";
  message: string;
  metadata: Record<string, unknown>;
}

function requireCredentialStorage(): void {
  if (!env.CONTROL_PLANE_ENC_KEY) {
    throw new IntegrationError(
      "Credential storage is not configured; set CONTROL_PLANE_ENC_KEY",
      503,
      "not_configured",
    );
  }
}

export class IntegrationError extends Error {
  constructor(
    message: string,
    readonly status = 400,
    readonly code = "invalid_request",
  ) {
    super(message);
  }
}

export const PROVIDERS: IntegrationProvider[] = [
  {
    id: "stripe",
    name: "Stripe",
    category: "Payments",
    description: "Refunds, charges, and dispute review with broker-held restricted keys.",
    authMode: "broker_managed",
    credentialFields: [
      {
        key: "secretKey",
        label: "Restricted key (optional)",
        placeholder: "rk_live_…",
        secret: true,
        help: "Used only to verify the connection. The broker still holds the signing credential.",
      },
    ],
    scopes: [
      { id: "refunds", label: "Create refunds", resource: "stripe:refunds.create", description: "Issue customer refunds within policy limits.", risk: "high" },
      { id: "charges", label: "Create charges", resource: "stripe:charges.create", description: "Charge a customer or saved payment method.", risk: "high" },
      { id: "disputes", label: "Read disputes", resource: "stripe:disputes.list", description: "Review dispute state and deadlines.", risk: "low" },
    ],
    sample: {
      tool: "stripe.refunds.create",
      args: { charge: "ch_integration_check", amount: 10, reason: "integration check" },
      intent: "Verify the Stripe integration path",
    },
    docsUrl: "https://thetessera.xyz/docs/integrations.html",
    maturity: "ga",
    color: "#635bff",
  },
  {
    id: "github",
    name: "GitHub",
    category: "Code & delivery",
    description: "Issues, pull requests, and repository actions with installation-scoped tokens.",
    authMode: "broker_managed",
    credentialFields: [
      {
        key: "token",
        label: "Fine-grained token (optional)",
        placeholder: "github_pat_…",
        secret: true,
        help: "Used only to verify the connection.",
      },
    ],
    scopes: [
      { id: "issues", label: "Create issues", resource: "github:issues.create", description: "Open tracking or remediation issues.", risk: "medium" },
      { id: "pulls", label: "Create pull requests", resource: "github:pulls.create", description: "Open code changes for review.", risk: "high" },
      { id: "repos", label: "Read repositories", resource: "github:repos.read", description: "Read repository metadata and files.", risk: "low" },
    ],
    sample: {
      tool: "github.issues.create",
      args: { repo: "acme/example", title: "Tessera integration check" },
      intent: "Verify the GitHub integration path",
    },
    docsUrl: "https://thetessera.xyz/docs/integrations.html",
    maturity: "ga",
    color: "#24292f",
  },
  {
    id: "slack",
    name: "Slack",
    category: "Communication",
    description: "Channel messages and history with a workspace bot token.",
    authMode: "api_key",
    credentialFields: [
      {
        key: "token",
        label: "Bot token",
        placeholder: "xoxb-…",
        secret: true,
        required: true,
        help: "Used to call auth.test and verify workspace access.",
      },
    ],
    scopes: [
      { id: "chat", label: "Post messages", resource: "slack:chat.postMessage", description: "Send a message to an approved channel.", risk: "medium" },
      { id: "history", label: "Read history", resource: "slack:conversations.history", description: "Read channel history for context.", risk: "low" },
    ],
    sample: {
      tool: "slack.chat.postMessage",
      args: { channel: "#integrations", text: "Tessera integration check" },
      intent: "Verify the Slack integration path",
    },
    docsUrl: "https://thetessera.xyz/docs/integrations.html",
    maturity: "preview",
    color: "#4a154b",
  },
  {
    id: "aws",
    name: "AWS",
    category: "Cloud",
    description: "S3 object access and STS role assumption through scoped credentials.",
    authMode: "broker_managed",
    credentialFields: [
      { key: "accessKeyId", label: "Access key ID (optional)", placeholder: "AKIA…", required: false },
      { key: "secretAccessKey", label: "Secret access key (optional)", placeholder: "••••", secret: true, required: false },
      { key: "region", label: "Region (optional)", placeholder: "us-east-1", required: false },
    ],
    scopes: [
      { id: "s3-read", label: "Read S3 objects", resource: "aws:s3:GetObject", description: "Read a scoped object from S3.", risk: "medium" },
      { id: "s3-write", label: "Write S3 objects", resource: "aws:s3:PutObject", description: "Write or replace a scoped object.", risk: "high" },
      { id: "role", label: "Assume role", resource: "aws:sts.assume_role", description: "Assume a scoped IAM role.", risk: "high" },
    ],
    sample: {
      tool: "aws:s3:GetObject",
      args: { bucket: "tessera-integration-check", key: "healthcheck.json" },
      intent: "Verify the AWS integration path",
    },
    docsUrl: "https://thetessera.xyz/docs/integrations.html",
    maturity: "ga",
    color: "#ff9900",
  },
  {
    id: "zendesk",
    name: "Zendesk",
    category: "Support",
    description: "Ticket creation and reads with a scoped API token.",
    authMode: "basic",
    credentialFields: [
      { key: "subdomain", label: "Zendesk subdomain", placeholder: "acme", required: true },
      { key: "email", label: "Agent email", placeholder: "ops@acme.com", required: true },
      { key: "apiToken", label: "API token", placeholder: "••••", secret: true, required: true },
    ],
    scopes: [
      { id: "tickets-create", label: "Create tickets", resource: "zendesk:tickets.create", description: "Open a support ticket.", risk: "medium" },
      { id: "tickets-read", label: "Read tickets", resource: "zendesk:tickets.read", description: "Read ticket state and comments.", risk: "low" },
    ],
    sample: {
      tool: "zendesk.tickets.create",
      args: { subject: "Tessera integration check", comment: { body: "Checking the Zendesk integration path." } },
      intent: "Verify the Zendesk integration path",
    },
    docsUrl: "https://thetessera.xyz/docs/integrations.html",
    maturity: "preview",
    color: "#03363d",
  },
  {
    id: "openai",
    name: "OpenAI",
    category: "Model provider",
    description: "Responses and model access with per-action authorization.",
    authMode: "api_key",
    credentialFields: [
      {
        key: "apiKey",
        label: "API key",
        placeholder: "sk-…",
        secret: true,
        required: true,
        help: "Used to call the models endpoint and verify access.",
      },
    ],
    scopes: [
      { id: "responses", label: "Create responses", resource: "openai:responses.create", description: "Run a model response request.", risk: "high" },
      { id: "models", label: "Read models", resource: "openai:models.read", description: "List available models.", risk: "low" },
    ],
    sample: {
      tool: "openai.responses.create",
      args: { model: "gpt-4.1-mini", input: "ping" },
      intent: "Verify the OpenAI integration path",
    },
    docsUrl: "https://thetessera.xyz/docs/integrations.html",
    maturity: "preview",
    color: "#10a37f",
  },
  {
    id: "anthropic",
    name: "Anthropic",
    category: "Model provider",
    description: "Claude message requests with policy-scoped API access.",
    authMode: "api_key",
    credentialFields: [
      {
        key: "apiKey",
        label: "API key",
        placeholder: "sk-ant-…",
        secret: true,
        required: true,
        help: "Used to call the models endpoint and verify access.",
      },
    ],
    scopes: [
      { id: "messages", label: "Create messages", resource: "anthropic:messages.create", description: "Run a Claude message request.", risk: "high" },
    ],
    sample: {
      tool: "anthropic.messages.create",
      args: { model: "claude-sonnet-4-5", max_tokens: 16, messages: [{ role: "user", content: "ping" }] },
      intent: "Verify the Anthropic integration path",
    },
    docsUrl: "https://thetessera.xyz/docs/integrations.html",
    maturity: "preview",
    color: "#d97757",
  },
  {
    id: "langchain",
    name: "LangChain",
    category: "Agent framework",
    description: "Tool wrapping through @tessera-verify/langchain.",
    authMode: "sdk",
    credentialFields: [],
    scopes: [
      { id: "tool-invoke", label: "Invoke tools", resource: "langchain:tool.invoke", description: "Authorize and record a wrapped LangChain tool.", risk: "medium" },
    ],
    sample: {
      tool: "langchain.tool.invoke",
      args: { tool: "integration_check" },
      intent: "Verify the LangChain SDK integration path",
    },
    docsUrl: "https://thetessera.xyz/docs/integrations.html",
    maturity: "sdk",
    color: "#1c3c3c",
  },
];

const providerMap = new Map(PROVIDERS.map((provider) => [provider.id, provider]));

export function providerById(id: string): IntegrationProvider | undefined {
  return providerMap.get(id);
}

function toolForResource(resource: string): string {
  const [provider, ...rest] = resource.split(":");
  return rest.length === 1 ? `${provider}.${rest[0]}` : resource;
}

type IntegrationRow = Record<string, any>;

function cleanCredential(input: unknown): Record<string, string> {
  if (!input || typeof input !== "object" || Array.isArray(input)) return {};
  return Object.fromEntries(
    Object.entries(input as Record<string, unknown>)
      .filter(([, value]) => typeof value === "string" && value.trim().length > 0)
      .map(([key, value]) => [key, String(value).trim().slice(0, 4096)]),
  );
}

function credentialHint(
  provider: IntegrationProvider,
  credential: Record<string, string>,
): string | null {
  const secret = provider.credentialFields.find((field) => field.secret && credential[field.key]);
  if (!secret) return credential && Object.keys(credential).length ? "configured" : null;
  const value = credential[secret.key]!;
  return `••••${value.slice(-4)}`;
}

function mergeMetadata(current: unknown, next: Record<string, unknown>): Record<string, unknown> {
  return {
    ...(current && typeof current === "object" && !Array.isArray(current)
      ? (current as Record<string, unknown>)
      : {}),
    ...next,
  };
}

function view(row: IntegrationRow): IntegrationView {
  const provider = providerById(String(row.provider));
  const scopeIds = Array.isArray(row.scopes) ? row.scopes.map(String) : [];
  const scopes = provider
    ? provider.scopes.filter((scope) => scopeIds.includes(scope.id))
    : scopeIds.map((id) => ({
        id,
        label: id,
        resource: id,
        description: "Custom integration scope",
        risk: "medium" as const,
      }));
  return {
    id: String(row.id),
    provider: String(row.provider),
    providerName: provider?.name ?? String(row.provider),
    providerCategory: provider?.category ?? "Integration",
    name: String(row.name),
    status: row.status as IntegrationStatus,
    authMode: row.auth_mode as IntegrationAuthMode,
    scopes,
    owner: row.owner_user_id
      ? {
          id: String(row.owner_user_id),
          email: String(row.owner_email ?? ""),
          name: row.owner_name ? String(row.owner_name) : null,
        }
      : null,
    environment: { id: String(row.environment_id), name: String(row.environment_name ?? "Environment") },
    hasCredential: Boolean(row.credential_ciphertext),
    credentialHint: row.credential_hint ? String(row.credential_hint) : null,
    metadata:
      row.metadata && typeof row.metadata === "object" && !Array.isArray(row.metadata)
        ? (row.metadata as Record<string, unknown>)
        : {},
    policyId: row.policy_id ? String(row.policy_id) : null,
    testActionId: row.test_action_id ? String(row.test_action_id) : null,
    lastSyncAt: row.last_sync_at ? new Date(row.last_sync_at).toISOString() : null,
    lastTestedAt: row.last_tested_at ? new Date(row.last_tested_at).toISOString() : null,
    lastTestOk: row.last_test_ok === null || row.last_test_ok === undefined ? null : Boolean(row.last_test_ok),
    lastTestMessage: row.last_test_message ? String(row.last_test_message) : null,
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
  };
}

async function rowsForEnvironment(orgId: string, environmentId: string): Promise<IntegrationRow[]> {
  return (await db()`
    SELECT ic.*, u.email AS owner_email, u.name AS owner_name, e.name AS environment_name
      FROM integration_connections ic
      LEFT JOIN users u ON u.id = ic.owner_user_id
      JOIN environments e ON e.id = ic.environment_id
     WHERE ic.org_id = ${orgId} AND ic.environment_id = ${environmentId}
     ORDER BY ic.created_at DESC
  `) as unknown as IntegrationRow[];
}

export async function listIntegrations(
  orgId: string,
  environmentId: string,
): Promise<IntegrationView[]> {
  return (await rowsForEnvironment(orgId, environmentId)).map(view);
}

async function rowById(orgId: string, environmentId: string, id: string): Promise<IntegrationRow | null> {
  const rows = await db()`
    SELECT ic.*, u.email AS owner_email, u.name AS owner_name, e.name AS environment_name
      FROM integration_connections ic
      LEFT JOIN users u ON u.id = ic.owner_user_id
      JOIN environments e ON e.id = ic.environment_id
     WHERE ic.id = ${id} AND ic.org_id = ${orgId} AND ic.environment_id = ${environmentId}
     LIMIT 1
  `;
  return (rows[0] as IntegrationRow | undefined) ?? null;
}

async function probeProvider(
  provider: IntegrationProvider,
  credential: Record<string, string>,
): Promise<ProbeResult> {
  const missing = provider.credentialFields
    .filter((field) => field.required && !credential[field.key])
    .map((field) => field.label);
  if (missing.length) {
    return {
      ok: false,
      mode: "configuration",
      message: `Add ${missing.join(", ")} to test this connection.`,
      metadata: {},
    };
  }

  if (provider.id === "aws") {
    const any = ["accessKeyId", "secretAccessKey", "region"].some((key) => credential[key]);
    const all = ["accessKeyId", "secretAccessKey", "region"].every((key) => credential[key]);
    if (any && !all) {
      return {
        ok: false,
        mode: "configuration",
        message: "AWS needs an access key ID, secret access key, and region together.",
        metadata: {},
      };
    }
    if (any && all) {
      return {
        ok: true,
        mode: "configuration",
        message: `AWS credential fields validated for ${credential.region}; the broker tests STS at issuance.`,
        metadata: { region: credential.region },
      };
    }
  }

  if (provider.authMode === "broker_managed" && !Object.keys(credential).length) {
    return {
      ok: true,
      mode: "broker_managed",
      message: "Broker-managed connection. The action broker holds the provider credential.",
      metadata: {},
    };
  }
  if (provider.authMode === "sdk") {
    return {
      ok: true,
      mode: "sdk",
      message: "SDK integration is available through @tessera-verify/langchain.",
      metadata: { package: "@tessera-verify/langchain" },
    };
  }
  if (env.NODE_ENV === "test") {
    return {
      ok: true,
      mode: "configuration",
      message: "Credential fields validated. Live network probe is disabled in tests.",
      metadata: {},
    };
  }

  const timeout = AbortSignal.timeout(8_000);
  try {
    if (provider.id === "github") {
      const response = await fetch("https://api.github.com/user", {
        headers: {
          accept: "application/vnd.github+json",
          authorization: `Bearer ${credential.token}`,
          "x-github-api-version": "2022-11-28",
        },
        signal: timeout,
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const body = (await response.json()) as { login?: string };
      return {
        ok: true,
        mode: "api_key",
        message: `GitHub accepted the token for ${body.login ?? "the account"}.`,
        metadata: {
          login: body.login ?? null,
          scopes: response.headers.get("x-oauth-scopes")?.split(",").map((value) => value.trim()).filter(Boolean) ?? [],
        },
      };
    }
    if (provider.id === "stripe") {
      const response = await fetch("https://api.stripe.com/v1/account", {
        headers: { authorization: `Bearer ${credential.secretKey}` },
        signal: timeout,
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const body = (await response.json()) as { id?: string; country?: string; business_profile?: { name?: string } };
      return {
        ok: true,
        mode: "api_key",
        message: `Stripe accepted the key for ${body.business_profile?.name ?? body.id ?? "the account"}.`,
        metadata: { accountId: body.id ?? null, country: body.country ?? null, accountName: body.business_profile?.name ?? null },
      };
    }
    if (provider.id === "slack") {
      const response = await fetch("https://slack.com/api/auth.test", {
        method: "POST",
        headers: { authorization: `Bearer ${credential.token}` },
        signal: timeout,
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const body = (await response.json()) as { ok?: boolean; team?: string; user?: string; error?: string };
      if (!body.ok) throw new Error(body.error ?? "token rejected");
      return {
        ok: true,
        mode: "api_key",
        message: `Slack accepted the token for ${body.team ?? "the workspace"}.`,
        metadata: { team: body.team ?? null, user: body.user ?? null },
      };
    }
    if (provider.id === "openai") {
      const response = await fetch("https://api.openai.com/v1/models", {
        headers: { authorization: `Bearer ${credential.apiKey}` },
        signal: timeout,
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const body = (await response.json()) as { data?: unknown[] };
      return {
        ok: true,
        mode: "api_key",
        message: `OpenAI accepted the key (${body.data?.length ?? 0} models visible).`,
        metadata: { models: body.data?.length ?? 0 },
      };
    }
    if (provider.id === "anthropic") {
      const response = await fetch("https://api.anthropic.com/v1/models", {
        headers: {
          "x-api-key": credential.apiKey ?? "",
          "anthropic-version": "2023-06-01",
        },
        signal: timeout,
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const body = (await response.json()) as { data?: unknown[] };
      return {
        ok: true,
        mode: "api_key",
        message: `Anthropic accepted the key (${body.data?.length ?? 0} models visible).`,
        metadata: { models: body.data?.length ?? 0 },
      };
    }
    if (provider.id === "zendesk") {
      if (!/^[a-z0-9-]+$/i.test(credential.subdomain ?? "")) {
        return { ok: false, mode: "configuration", message: "Zendesk subdomain contains invalid characters.", metadata: {} };
      }
      const auth = Buffer.from(`${credential.email}/token:${credential.apiToken}`).toString("base64");
      const response = await fetch(
        `https://${credential.subdomain ?? ""}.zendesk.com/api/v2/users/me.json`,
        { headers: { authorization: `Basic ${auth}` }, signal: timeout },
      );
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const body = (await response.json()) as { user?: { name?: string; email?: string } };
      return {
        ok: true,
        mode: "basic",
        message: `Zendesk accepted the token for ${body.user?.name ?? "the agent"}.`,
        metadata: { agent: body.user?.name ?? null, email: body.user?.email ?? null },
      };
    }
    return {
      ok: false,
      mode: "configuration",
      message: `No live probe is available for ${provider.name}.`,
      metadata: {},
    };
  } catch (error) {
    return {
      ok: false,
      mode: provider.authMode,
      message: `${provider.name} rejected the connection: ${error instanceof Error ? error.message : "network error"}.`,
      metadata: {},
    };
  }
}

async function decryptCredential(row: IntegrationRow): Promise<Record<string, string>> {
  if (!row.credential_ciphertext) return {};
  try {
    return cleanCredential(JSON.parse(decryptSecret(String(row.credential_ciphertext))));
  } catch {
    throw new IntegrationError("The stored credential could not be decrypted", 500, "credential_error");
  }
}

function maxRisk(provider: IntegrationProvider, scopeIds: string[]): "low" | "medium" | "high" {
  const rank = { low: 0, medium: 1, high: 2 };
  return provider.scopes
    .filter((scope) => scopeIds.includes(scope.id))
    .reduce<"low" | "medium" | "high">((current, scope) => (rank[scope.risk] > rank[current] ? scope.risk : current), "low");
}

export async function createIntegration(input: {
  orgId: string;
  environment: Environment & { broker_key_enc: string | null };
  user: { id: string; email: string };
  providerId: string;
  name?: string;
  scopes?: string[];
  credential?: unknown;
}): Promise<{ integration: IntegrationView; warning?: string }> {
  const provider = providerById(input.providerId);
  if (!provider) throw new IntegrationError("Unknown integration provider");
  const existing = await db()`
    SELECT id FROM integration_connections
     WHERE environment_id = ${input.environment.id} AND provider = ${provider.id}
     LIMIT 1
  `;
  if (existing[0]) {
    throw new IntegrationError(`${provider.name} is already connected in this environment`, 409, "conflict");
  }
  const scopeIds = Array.isArray(input.scopes) && input.scopes.length
    ? [...new Set(input.scopes.map(String))]
    : provider.scopes.map((scope) => scope.id);
  const invalid = scopeIds.filter((id) => !provider.scopes.some((scope) => scope.id === id));
  if (invalid.length) throw new IntegrationError(`Unknown scope: ${invalid.join(", ")}`);
  const id = uuid();
  const now = new Date();
  const credential = cleanCredential(input.credential);
  if (Object.keys(credential).length) requireCredentialStorage();
  const encrypted = Object.keys(credential).length ? encryptSecret(JSON.stringify(credential)) : null;
  const policyId = `integration-${provider.id}-${id.slice(0, 8)}`;
  const grants = provider.scopes
    .filter((scope) => scopeIds.includes(scope.id))
    .map((scope) => ({ resource: scope.resource, constraints: [] }));
  try {
    await broker.putPolicy(input.environment, policyId, {
      version: 1,
      name: `${provider.name} baseline`,
      fail_open: false,
      mode: "enforce",
      grants,
      limits: {},
    });
  } catch (error) {
    throw new IntegrationError(
      error instanceof Error ? `Could not create the first policy: ${error.message}` : "Could not create the first policy",
      502,
      "broker_error",
    );
  }

  const testScope = provider.scopes.find((scope) => scopeIds.includes(scope.id)) ?? provider.scopes[0]!;
  let testActionId: string | null = null;
  let testAllowed = false;
  let testWarning: string | undefined;
  try {
    const response = await broker.authorize(input.environment, {
      agentId: "tessera-integration-check",
      userId: input.user.email,
      tool: toolForResource(testScope.resource),
      intent: provider.sample.intent,
      args: provider.sample.args,
      requestedScopes: provider.scopes.filter((scope) => scopeIds.includes(scope.id)).map((scope) => scope.resource),
      riskClass: maxRisk(provider, scopeIds),
      agentMeta: { agentVersion: "integration-setup", environment: input.environment.name },
    });
    await persistAction(input.environment, response);
    testActionId = String(response.actionId ?? (response.receipt as Record<string, any> | undefined)?.actionId ?? "") || null;
    testAllowed =
      (response.receipt as Record<string, any> | undefined)?.authorization?.decision === "allow";
    if (!testAllowed) {
      testWarning = "The test action was denied; verify the baseline policy";
    }
    const receiptId = String(response.receiptId ?? "");
    if (testActionId && receiptId) {
      try {
        const recorded = await broker.record(input.environment, {
          agentId: "tessera-integration-check",
          receiptId,
          resultHash: `0x${sha256(`${provider.id}:${id}`)}`,
          status: "success",
        });
        await persistOutcome(input.environment, receiptId, recorded);
      } catch {
        // The authorization record is still useful if the outcome cannot be appended.
      }
    }
  } catch (error) {
    testWarning = error instanceof Error ? error.message : "The policy test action could not be issued";
  }

  const probe = await probeProvider(provider, credential);
  const ok = probe.ok && Boolean(testActionId) && testAllowed;
  const message = testWarning
    ? `Policy created; test action failed: ${testWarning}`
    : `${probe.message}${testActionId ? " Test action allowed and recorded." : ""}`;
  const status: IntegrationStatus = ok ? "connected" : "needs_attention";

  try {
    await db()`
      INSERT INTO integration_connections (
        id, org_id, environment_id, provider, name, status, auth_mode, scopes,
        owner_user_id, credential_ciphertext, credential_hint, metadata, policy_id,
        test_action_id, last_sync_at, last_tested_at, last_test_ok, last_test_message,
        created_at, updated_at
      ) VALUES (
        ${id}, ${input.orgId}, ${input.environment.id}, ${provider.id},
        ${input.name?.trim() || provider.name}, ${status}, ${provider.authMode},
        ${db().json(scopeIds as never)}, ${input.user.id}, ${encrypted},
        ${credentialHint(provider, credential)}, ${db().json(mergeMetadata({}, probe.metadata) as never)},
        ${policyId}, ${testActionId}, ${now.toISOString()}, ${now.toISOString()}, ${ok},
        ${message}, ${now.toISOString()}, ${now.toISOString()}
      )
    `;
  } catch (error) {
    if (typeof error === "object" && error && "code" in error && error.code === "23505") {
      throw new IntegrationError(`${provider.name} is already connected in this environment`, 409, "conflict");
    }
    throw error;
  }
  await audit({
    orgId: input.orgId,
    actorUserId: input.user.id,
    action: "integration.connected",
    target: id,
    details: { provider: provider.id, environmentId: input.environment.id, policyId, testActionId },
  });
  const row = await rowById(input.orgId, input.environment.id, id);
  if (!row) throw new IntegrationError("Integration was created but could not be read", 500);
  return { integration: view(row), warning: testWarning };
}

export async function testIntegration(input: {
  orgId: string;
  environment: Environment & { broker_key_enc: string | null };
  user: { id: string };
  id: string;
}): Promise<{ integration: IntegrationView; probe: ProbeResult }> {
  const row = await rowById(input.orgId, input.environment.id, input.id);
  if (!row) throw new IntegrationError("Integration not found", 404, "not_found");
  const provider = providerById(String(row.provider));
  if (!provider) throw new IntegrationError("Unknown integration provider", 400);
  const credential = await decryptCredential(row);
  const probe = await probeProvider(provider, credential);
  const testActionId = row.test_action_id ? String(row.test_action_id) : null;
  const ok = probe.ok && Boolean(testActionId);
  const message = testActionId
    ? `${probe.message} Test action: ${testActionId}.`
    : `${probe.message} No test action is linked yet.`;
  const now = new Date();
  await db()`
    UPDATE integration_connections
       SET status = ${ok ? "connected" : "needs_attention"},
           metadata = ${db().json(mergeMetadata(row.metadata, { lastProbe: probe.metadata, lastProbeMode: probe.mode }) as never)},
           last_sync_at = ${now.toISOString()},
           last_tested_at = ${now.toISOString()},
           last_test_ok = ${ok},
           last_test_message = ${message},
           updated_at = ${now.toISOString()}
     WHERE id = ${input.id} AND org_id = ${input.orgId}
  `;
  await audit({
    orgId: input.orgId,
    actorUserId: input.user.id,
    action: "integration.tested",
    target: input.id,
    details: { provider: provider.id, ok, mode: probe.mode },
  });
  const updated = await rowById(input.orgId, input.environment.id, input.id);
  if (!updated) throw new IntegrationError("Integration not found", 404, "not_found");
  return { integration: view(updated), probe };
}

export async function rotateIntegration(input: {
  orgId: string;
  environment: Environment & { broker_key_enc: string | null };
  user: { id: string };
  id: string;
  credential?: unknown;
}): Promise<IntegrationView> {
  const row = await rowById(input.orgId, input.environment.id, input.id);
  if (!row) throw new IntegrationError("Integration not found", 404, "not_found");
  const provider = providerById(String(row.provider));
  if (!provider) throw new IntegrationError("Unknown integration provider", 400);
  if (!provider.credentialFields.length) {
    throw new IntegrationError(`${provider.name} does not use a stored credential`, 400);
  }
  const credential = cleanCredential(input.credential);
  if (!Object.keys(credential).length) {
    throw new IntegrationError("Provide the replacement credential", 400);
  }
  requireCredentialStorage();
  const now = new Date();
  await db()`
    UPDATE integration_connections
       SET credential_ciphertext = ${encryptSecret(JSON.stringify(credential))},
           credential_hint = ${credentialHint(provider, credential)},
           status = 'needs_attention',
           last_test_ok = NULL,
           last_test_message = 'Credential rotated; run Test connection.',
           updated_at = ${now.toISOString()}
     WHERE id = ${input.id} AND org_id = ${input.orgId}
  `;
  await audit({
    orgId: input.orgId,
    actorUserId: input.user.id,
    action: "integration.credential_rotated",
    target: input.id,
    details: { provider: provider.id },
  });
  const updated = await rowById(input.orgId, input.environment.id, input.id);
  if (!updated) throw new IntegrationError("Integration not found", 404, "not_found");
  return view(updated);
}
