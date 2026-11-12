export interface Me {
  user: { id: string; email: string; name: string | null };
  org: { id: string; name: string; slug: string; plan: string };
  role: "owner" | "admin" | "member" | "viewer";
  environments: Array<{ id: string; name: string; slug: string; broker_tenant: string }>;
}

export interface ActionSummary {
  actionId: string;
  environmentId: string;
  agentId: string;
  principalId: string;
  tool: string;
  decision: "allow" | "deny";
  outcomeStatus: string | null;
  policyId: string;
  policyVersion: number;
  policyHash: string | null;
  credentialIssuer: string | null;
  credentialThumbprint: string | null;
  receiptId: string;
  createdAt: string;
  completedAt: string | null;
  verified: boolean | null;
}

export interface ActionReview {
  id: string;
  status: "pending" | "approved" | "rejected";
  reason: string | null;
  resolution_note: string | null;
  created_at: string;
  resolved_at: string | null;
}

export interface ActionDetail extends ActionSummary {
  payload: {
    authorization?: Record<string, unknown>;
    outcome?: Record<string, unknown> | null;
  };
  review?: ActionReview | null;
  verification: {
    valid: boolean;
    errors: string[];
    recovered?: string;
    matchesExpected?: boolean;
  } | null;
}

export interface VerificationLink {
  id: string;
  actionId: string;
  expiresAt: string;
  url: string;
}

export interface AgentSummary {
  agent_id: string;
  actions: number;
  last_seen: string;
  denied: number;
  succeeded: number;
}

export interface Usage {
  plan: string;
  limit: number;
  used: number;
  remaining: number;
  items: Array<{ day: string; actions: number; allowed: number; denied: number }>;
}

export interface AgentKey {
  id: string;
  name: string;
  prefix: string;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
  expires_at: string | null;
  delegation_mode: "caller" | "owner" | "token";
  delegated_user_id: string | null;
  delegated_email: string | null;
  delegated_name: string | null;
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code?: string,
  ) {
    super(message);
  }
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    ...init,
    credentials: "include",
    headers: {
      "content-type": "application/json",
      ...(init.headers ?? {}),
    },
  });
  const text = await response.text();
  let body: any = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  if (!response.ok) {
    throw new ApiError(
      body?.error?.message ?? body?.error ?? `Request failed (${response.status})`,
      response.status,
      body?.error?.code,
    );
  }
  return body as T;
}

export async function getMe(): Promise<Me> {
  return api<Me>("/v1/me");
}

export async function logout(): Promise<void> {
  await api("/auth/logout", { method: "POST" });
}

export function environmentQuery(environmentId?: string): string {
  return environmentId ? `?environmentId=${encodeURIComponent(environmentId)}` : "";
}

export interface AuthConfig {
  devAuth: boolean;
  oidc: boolean;
}

export async function getAuthConfig(): Promise<AuthConfig> {
  return api<AuthConfig>("/auth/config");
}
