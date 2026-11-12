export type CoverageStatus = "covered" | "partial" | "gap";

export interface EvidenceSignal {
  id: string;
  label: string;
  value: number;
  total: number;
  status: CoverageStatus;
  detail: string;
  gap?: string;
}

export interface EvidenceControl extends EvidenceSignal {
  title: string;
  question: string;
  evidence: string[];
}

export interface EvidenceFramework {
  id: string;
  name: string;
  description: string;
  controls: EvidenceControl[];
  covered: number;
  partial: number;
  gap: number;
  readiness: number;
}

export interface EvidenceRecord {
  actionId: string;
  agentId: string;
  principalId: string | null;
  tool: string;
  decision: string;
  outcomeStatus: string | null;
  outcomeSource: string | null;
  policyId: string | null;
  policyVersion: number | null;
  receiptId: string;
  createdAt: string;
  verified: boolean | null;
}

export interface EvidenceSummary {
  version: 1;
  generatedAt: string;
  orgName: string;
  environmentName: string;
  scope: { type: "environment" | "agent"; agentId: string | null };
  window: { since: string; until: string };
  recipients: string[];
  readiness: {
    score: number;
    status: "ready" | "partial" | "gap";
    explanation: string;
    covered: number;
    partial: number;
    gap: number;
    controls: number;
  };
  inventory: {
    actions: number;
    allowed: number;
    denied: number;
    completed: number;
    failed: number;
    verified: number;
    agents: number;
    policies: number;
    reviews: number;
    transitions: number;
    verificationLinks: number;
    agentKeys: number;
    evidencePacks: number;
    receipts: number;
    anchors: number;
  };
  signals: EvidenceSignal[];
  frameworks: EvidenceFramework[];
  gaps: string[];
  notes: string[];
  delta: {
    sincePackId: string;
    sincePackAt: string;
    actions: number;
    denied: number;
    reviews: number;
    transitions: number;
    policyChanges: number;
  } | null;
  policies: Array<{ id: string; name: string; version: number; grants: unknown[] }>;
  records: EvidenceRecord[];
  reviews: {
    total: number;
    pending: number;
    approved: number;
    rejected: number;
    items: Array<{
      id: string;
      actionId: string;
      status: string;
      reason: string | null;
      resolutionNote: string | null;
      createdAt: string;
      resolvedAt: string | null;
    }>;
  };
  transitions: Array<{ id: string; kind: string; target: string; at: string; eventHash: string }>;
  verificationLinks: Array<{ id: string; actionId: string; createdAt: string; expiresAt: string }>;
  proof: {
    chainsVerified: boolean | null;
    keyEventsVerified: boolean | null;
    chainReceipts: number;
    anchors: number;
    anchorLatest: string | null;
    unanchoredAgents: number;
  };
}

export interface EvidencePack {
  id: string;
  environment_id: string;
  status: string;
  filters: Record<string, unknown>;
  summary: EvidenceSummary | Record<string, never>;
  created_at: string;
  expires_at: string | null;
  share_expires_at?: string | null;
  hasShare?: boolean;
  downloadUrl: string;
  reportUrl: string;
}

export interface SharedEvidencePack {
  pack: {
    id: string;
    createdAt: string;
    expiresAt: string | null;
    shareExpiresAt: string;
    summary: EvidenceSummary;
  };
  org: { name: string };
  environment: { name: string };
  downloadUrl: string;
  reportUrl: string;
  verifyUrl: string;
  securityContact: string;
}

export function isEvidenceSummary(value: unknown): value is EvidenceSummary {
  return Boolean(value && typeof value === "object" && (value as { version?: unknown }).version === 1);
}

export function readinessTone(status: string): "ok" | "warn" | "bad" {
  return status === "ready" || status === "covered" ? "ok" : status === "partial" ? "warn" : "bad";
}

export function coverageLabel(status: CoverageStatus): string {
  return status === "covered" ? "Covered" : status === "partial" ? "Partial" : "Gap";
}

export const FRAMEWORK_OPTIONS = [
  { id: "soc2", name: "SOC 2" },
  { id: "iso42001", name: "ISO 42001" },
  { id: "eu-ai-act", name: "EU AI Act" },
  { id: "nist-ai-rmf", name: "NIST AI RMF" },
  { id: "dora", name: "DORA" },
] as const;
