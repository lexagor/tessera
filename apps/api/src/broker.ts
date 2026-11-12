import { verifyAction, verifyReceipt, type VerifyDomain } from "@tessera/verify";
import type { AnyReceipt } from "@tessera/receipt-schema";

import { decryptSecret } from "./crypto.js";
import { env } from "./env.js";
import type { Environment } from "./types.js";

export class BrokerError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body: unknown,
  ) {
    super(message);
  }
}

interface EnvironmentWithKey extends Environment {
  broker_key_enc: string | null;
}

function brokerHeaders(environment?: EnvironmentWithKey): Record<string, string> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
  };
  if (environment?.broker_key_enc) {
    headers.authorization = `Bearer ${decryptSecret(environment.broker_key_enc)}`;
  } else if (env.BROKER_DEMO_ALLOW && environment) {
    headers["x-tessera-tenant"] = environment.broker_tenant;
  } else if (!environment && env.BROKER_ADMIN_KEY) {
    headers.authorization = `Bearer ${env.BROKER_ADMIN_KEY}`;
  }
  if (!environment && env.BROKER_ADMIN_TOKEN) {
    headers["x-tessera-admin"] = env.BROKER_ADMIN_TOKEN;
  }
  return headers;
}

async function request<T>(
  path: string,
  init: RequestInit = {},
  environment?: EnvironmentWithKey,
): Promise<T> {
  const response = await fetch(`${env.BROKER_URL.replace(/\/$/, "")}${path}`, {
    ...init,
    headers: { ...brokerHeaders(environment), ...(init.headers ?? {}) },
    signal: AbortSignal.timeout(15_000),
  });
  const text = await response.text();
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  if (!response.ok) {
    const message =
      body && typeof body === "object" && "error" in body
        ? String((body as { error: unknown }).error)
        : `broker returned ${response.status}`;
    throw new BrokerError(message, response.status, body);
  }
  return body as T;
}

export async function createBrokerKey(tenant: string, name: string): Promise<string> {
  if (!env.BROKER_ADMIN_KEY) {
    if (env.BROKER_DEMO_ALLOW) return "";
    throw new BrokerError(
      "BROKER_ADMIN_KEY is not configured; create an environment key manually",
      503,
      null,
    );
  }
  const body = await request<{ key: string }>("/v1/keys", {
    method: "POST",
    body: JSON.stringify({
      tenant,
      name,
      allowedCapabilities: ["authorize", "record", "proxy", "read"],
    }),
  });
  return body.key;
}

export async function revokeBrokerKey(
  environment: EnvironmentWithKey,
  keyPrefix: string,
): Promise<void> {
  // The broker only exposes keys by id; deleting an environment is best-effort here.
  // The environment key remains valid until rotated if this lookup is unavailable.
  void environment;
  void keyPrefix;
}

export function authorize(
  environment: EnvironmentWithKey,
  body: unknown,
  idempotencyKey?: string,
): Promise<Record<string, unknown>> {
  return request(
    "/v1/authorize",
    {
      method: "POST",
      body: JSON.stringify(body),
      headers: idempotencyKey ? { "idempotency-key": idempotencyKey } : {},
    },
    environment,
  );
}

export function record(
  environment: EnvironmentWithKey,
  body: unknown,
  idempotencyKey?: string,
): Promise<Record<string, unknown>> {
  return request(
    "/v1/record",
    {
      method: "POST",
      body: JSON.stringify(body),
      headers: idempotencyKey ? { "idempotency-key": idempotencyKey } : {},
    },
    environment,
  );
}

export function proxy(
  environment: EnvironmentWithKey,
  body: unknown,
  idempotencyKey?: string,
): Promise<Record<string, unknown>> {
  return request(
    "/v1/proxy",
    {
      method: "POST",
      body: JSON.stringify(body),
      headers: idempotencyKey ? { "idempotency-key": idempotencyKey } : {},
    },
    environment,
  );
}

async function requestBytes(
  path: string,
  init: RequestInit = {},
  environment?: EnvironmentWithKey,
): Promise<Uint8Array> {
  const response = await fetch(`${env.BROKER_URL.replace(/\/$/, "")}${path}`, {
    ...init,
    headers: { ...brokerHeaders(environment), ...(init.headers ?? {}) },
    signal: AbortSignal.timeout(60_000),
  });
  if (!response.ok) {
    const text = await response.text();
    throw new BrokerError(
      text || `broker returned ${response.status}`,
      response.status,
      text,
    );
  }
  return new Uint8Array(await response.arrayBuffer());
}

export function exportTenantArchive(
  environment: EnvironmentWithKey,
): Promise<Uint8Array> {
  return requestBytes("/v1/export/tenant/archive", {}, environment);
}

export function listPolicies(
  environment: EnvironmentWithKey,
): Promise<Record<string, unknown>> {
  return request("/v1/policies", {}, environment);
}

export function getPolicy(
  environment: EnvironmentWithKey,
  id: string,
): Promise<Record<string, unknown>> {
  return request(`/v1/policies/${encodeURIComponent(id)}`, {}, environment);
}

export function putPolicy(
  environment: EnvironmentWithKey,
  id: string,
  body: unknown,
): Promise<Record<string, unknown>> {
  return request(
    `/v1/policies/${encodeURIComponent(id)}`,
    { method: "PUT", body: JSON.stringify(body) },
    environment,
  );
}

export function deletePolicy(
  environment: EnvironmentWithKey,
  id: string,
): Promise<Record<string, unknown>> {
  return request(
    `/v1/policies/${encodeURIComponent(id)}`,
    { method: "DELETE" },
    environment,
  );
}

export function proposePolicy(
  environment: EnvironmentWithKey,
): Promise<Record<string, unknown>> {
  return request("/v1/policies/propose", {}, environment);
}

export function appendTransition(
  environment: EnvironmentWithKey,
  body: unknown,
): Promise<Record<string, unknown>> {
  return request(
    "/v1/transitions",
    { method: "POST", body: JSON.stringify(body) },
    environment,
  );
}

export function keyEvents(
  environment: EnvironmentWithKey,
  limit = 500,
): Promise<Record<string, unknown>> {
  return request(`/v1/key-events?limit=${limit}`, {}, environment);
}

export function chain(
  environment: EnvironmentWithKey,
  agentId: string,
  query = "",
): Promise<Record<string, unknown>> {
  return request(
    `/v1/chain/${encodeURIComponent(agentId)}${query}`,
    {},
    environment,
  );
}

let cachedDomain: {
  domain: VerifyDomain;
  signer: string;
  signers: string[];
  expires: number;
} | null = null;

export async function verifyDomain(): Promise<{
  domain: VerifyDomain;
  signer: string;
  signers: string[];
}> {
  if (cachedDomain && cachedDomain.expires > Date.now()) return cachedDomain;
  const body = await request<{
    chainId: number;
    verifyingContract: string;
    signer: string;
    signers?: string[];
  }>("/v1/verify/domain");
  cachedDomain = {
    domain: {
      chainId: body.chainId,
      verifyingContract: body.verifyingContract,
    },
    signer: body.signer,
    signers: (body.signers?.length ? body.signers : [body.signer]).map((value) =>
      value.toLowerCase(),
    ),
    expires: Date.now() + 300_000,
  };
  return cachedDomain;
}

export async function verifyRecord(
  authorization: AnyReceipt,
  outcome: AnyReceipt | null,
): Promise<{ valid: boolean; errors: string[]; recovered?: string }> {
  const { domain, signers } = await verifyDomain();
  const result = outcome
    ? verifyAction(authorization, outcome, domain)
    : verifyReceipt(authorization, domain);
  const recovered = result.recovered?.toLowerCase();
  if (result.valid && recovered && !signers.includes(recovered)) {
    return {
      ...result,
      valid: false,
      errors: [...result.errors, "recovered signer is not an accepted broker signer"],
    };
  }
  return result;
}
