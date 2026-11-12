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
  sample: { tool: string; args: Record<string, unknown>; intent: string };
  docsUrl: string;
  maturity: "ga" | "preview" | "sdk";
  color: string;
}

export interface IntegrationConnection {
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

export interface IntegrationsResponse {
  items: IntegrationConnection[];
  providers: IntegrationProvider[];
}

export interface ProbeResult {
  ok: boolean;
  mode: string;
  message: string;
  metadata: Record<string, unknown>;
}

export function integrationStatusTone(status: IntegrationStatus): "ok" | "warn" | "bad" | "muted" {
  if (status === "connected") return "ok";
  if (status === "needs_attention") return "warn";
  if (status === "disabled") return "muted";
  return "bad";
}

export function integrationStatusLabel(status: IntegrationStatus): string {
  return status === "connected" ? "Connected" : status === "needs_attention" ? "Needs attention" : "Disabled";
}

export function riskTone(risk: IntegrationScope["risk"]): "ok" | "warn" | "bad" {
  return risk === "low" ? "ok" : risk === "medium" ? "warn" : "bad";
}

export function authModeLabel(mode: IntegrationAuthMode): string {
  return mode === "broker_managed"
    ? "Broker-managed"
    : mode === "api_key"
      ? "API key"
      : mode === "basic"
        ? "Basic auth"
        : "SDK";
}

export function providerMark(provider: string): string {
  return provider.slice(0, 1).toUpperCase();
}
