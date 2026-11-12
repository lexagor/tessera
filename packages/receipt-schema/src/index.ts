import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils";

/**
 * Receipt types, canonical hashing, and EIP-712 typed-data definitions.
 *
 * The EIP-712 domain/types intentionally mirror the authorization-grant pattern used
 * elsewhere in the stack (hash large payloads off-chain, sign a compact digest).
 */

export interface Receipt {
  v: 1;
  tenant: string;
  agent: string;
  user: string;
  intentHash: string;
  authorization: {
    decision: "allow" | "deny";
    policy: string;
    policyVersion: number;
    resource: string;
    anomalyScore: number;
    policyHash?: string;
  };
  call: { tool: string; argsHash: string; resultHash?: string; toolHash?: string };
  grant: {
    provider: string;
    ttlS: number;
    singleUse: boolean;
    status: "issued" | "used" | "expired" | "revoked";
  };
  ts: string;
  nonce: string;
  prev?: string | null;
  authorizationReceiptId?: string;
  signature?: string | null;
}

export interface PrincipalRef {
  principalId: string;
  principalType: string;
  authorityRef: string;
  authorityHash: string;
  verifiedAt?: string;
  verificationMethod: string;
}

export interface AgentRef {
  agentId: string;
  agentVersion?: string;
  modelId?: string;
  operatorId?: string;
  environment?: string;
}

export interface IntentRef {
  intentHash: string;
  requestedScopes?: string[];
  riskClass?: string;
  declaredPurpose?: string;
}

export interface PolicyRef {
  policyId: string;
  policyVersion: number;
  policyHash: string;
  decision: "allow" | "deny";
  reasonCode?: string;
  evaluatedInputsHash?: string;
  evaluatorVersion?: string;
}

export interface CredentialRef {
  issuer: string;
  credentialType: string;
  thumbprint: string;
  scopes?: string[];
  ttlSeconds: number;
  singleUse: boolean;
  issuanceId: string;
}

export interface OutcomeRef {
  status: "success" | "failure" | "denied" | "timeout" | "unknown" | string;
  source?: "broker_observed" | "agent_reported";
  resultHash?: string;
  errorClass?: string;
  externalRef?: string;
  completedAt: string;
}

export interface AttestationRef {
  signerKeyId: string;
  signatureAlg: string;
  timestamp?: string;
  transparencyLogIndex?: number;
  anchorRef?: string;
}

/**
 * V2 action record. The authorization record and its outcome record share `actionId`;
 * the outcome record carries `outcome` and links to the authorization via
 * `authorizationReceiptId` (or the legacy immediate `prev`).
 */
export interface ReceiptV2 extends Omit<Receipt, "v"> {
  v: 2;
  actionId: string;
  principal: PrincipalRef;
  agentMeta: AgentRef;
  intent: IntentRef;
  policy: PolicyRef;
  credential?: CredentialRef;
  outcome?: OutcomeRef;
  authorizationReceiptId?: string;
  attestation: AttestationRef;
}

export type AnyReceipt = Receipt | ReceiptV2;

/** EIP-712 domain for receipt signing. */
export const RECEIPT_DOMAIN = {
  name: "TesseraReceipt",
  version: "1",
} as const;

/** EIP-712 struct definition for the compact signed digest. */
export const RECEIPT_TYPES = {
  Receipt: [
    { name: "payloadHash", type: "bytes32" },
    { name: "prev", type: "bytes32" },
    { name: "agent", type: "address" },
    { name: "nonce", type: "bytes32" },
  ],
} as const;

/**
 * Deterministic canonical JSON: keys sorted, no insignificant whitespace, integral floats
 * emitted without a fractional part. Must match the Rust broker's `canonical::canonicalize`.
 */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") {
    if (typeof value === "number" && Number.isInteger(value)) return String(value);
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalize(v)}`).join(",")}}`;
}

/** Keccak-256 of a UTF-8 string or byte array, hex-encoded with a `0x` prefix. */
export function keccak256Hex(input: string | Uint8Array): string {
  const bytes = typeof input === "string" ? utf8ToBytes(input) : input;
  return `0x${bytesToHex(keccak_256(bytes))}`;
}

/**
 * Hash of an MCP tool definition (name, description, input/output schema, annotations).
 * Matches the Rust broker's `tool_pins::definition_hash`, so clients can send the value
 * the broker compares against the approved pin.
 */
export function toolDefinitionHash(definition: unknown): string {
  return keccak256Hex(canonicalize(definition));
}

/**
 * `keccak256(canonicalize(receipt without "signature"))`.
 * Matches the Rust broker's `receipt::payload_hash_hex`.
 */
export function payloadHash(receipt: AnyReceipt): string {
  const clone: Record<string, unknown> = { ...(receipt as unknown as Record<string, unknown>) };
  delete clone.signature;
  return keccak256Hex(canonicalize(clone));
}

export function isReceiptV2(receipt: AnyReceipt): receipt is ReceiptV2 {
  return receipt.v === 2;
}

const HASH_RE = /^0x[0-9a-fA-F]{64}$/;

/** Structural validation for v2 records; v1 records are returned unchanged. */
export function validateReceipt(receipt: AnyReceipt): string[] {
  const errors: string[] = [];
  const version = (receipt as { v: number }).v;
  if (version === 1) return errors;
  if (version !== 2) {
    errors.push(`unsupported receipt version ${String(version)}`);
    return errors;
  }
  const rec = receipt as ReceiptV2;
  if (!HASH_RE.test(rec.intentHash)) {
    errors.push("intentHash must be a 32-byte hash");
  }
  const grantStatuses = new Set(["issued", "used", "denied", "expired", "revoked"]);
  if (!grantStatuses.has(rec.grant.status)) {
    errors.push("grant.status is not recognized");
  }
  if (!rec.actionId || rec.actionId.length > 128) {
    errors.push("actionId is required (max 128 chars)");
  }
  if (!rec.principal) errors.push("principal is required");
  else {
    if (!rec.principal.principalId) errors.push("principal.principalId is required");
    if (rec.user !== rec.principal.principalId) {
      errors.push("user must match principal.principalId");
    }
    if (!rec.principal.principalType) errors.push("principal.principalType is required");
    if (!rec.principal.authorityRef) errors.push("principal.authorityRef is required");
    if (!HASH_RE.test(rec.principal.authorityHash)) {
      errors.push("principal.authorityHash must be a 32-byte hash");
    }
    if (!rec.principal.verificationMethod) {
      errors.push("principal.verificationMethod is required");
    }
  }
  if (!rec.agentMeta) errors.push("agentMeta is required");
  else if (rec.agentMeta.agentId !== rec.agent) {
    errors.push("agentMeta.agentId must match agent");
  }
  if (!rec.intent) errors.push("intent is required");
  else if (rec.intent.intentHash !== rec.intentHash) {
    errors.push("intent.intentHash must match intentHash");
  }
  if (!rec.policy) errors.push("policy is required");
  else {
    if (!HASH_RE.test(rec.policy.policyHash)) {
      errors.push("policy.policyHash must be a 32-byte hash");
    }
    if (rec.policy.policyId !== rec.authorization.policy) {
      errors.push("policy.policyId must match authorization.policy");
    }
    if (rec.policy.policyVersion !== rec.authorization.policyVersion) {
      errors.push("policy.policyVersion must match authorization.policyVersion");
    }
    if (rec.policy.decision !== rec.authorization.decision) {
      errors.push("policy.decision must match authorization.decision");
    }
    if (rec.authorization.policyHash !== rec.policy.policyHash) {
      errors.push("authorization.policyHash must match policy.policyHash");
    }
  }
  if (!rec.attestation) errors.push("attestation is required");
  else {
    if (!rec.attestation.signerKeyId) errors.push("attestation.signerKeyId is required");
    if (!rec.attestation.signatureAlg) errors.push("attestation.signatureAlg is required");
  }
  if (rec.authorizationReceiptId && !HASH_RE.test(rec.authorizationReceiptId)) {
    errors.push("authorizationReceiptId must be a 32-byte hash");
  }
  if (
    rec.outcome?.source &&
    rec.outcome.source !== "broker_observed" &&
    rec.outcome.source !== "agent_reported"
  ) {
    errors.push("outcome.source must be broker_observed or agent_reported");
  }
  if (rec.authorization.decision === "allow" && !rec.credential) {
    errors.push("allowed records require credential");
  }
  if (rec.credential) {
    if (!HASH_RE.test(rec.credential.thumbprint)) {
      errors.push("credential.thumbprint must be a 32-byte hash");
    }
    if (rec.credential.issuer !== rec.grant.provider) {
      errors.push("credential.issuer must match grant.provider");
    }
    if (rec.credential.ttlSeconds !== rec.grant.ttlS) {
      errors.push("credential.ttlSeconds must match grant.ttlS");
    }
    if (rec.credential.singleUse !== rec.grant.singleUse) {
      errors.push("credential.singleUse must match grant.singleUse");
    }
  }
  if (rec.call.toolHash && !HASH_RE.test(rec.call.toolHash)) {
    errors.push("call.toolHash must be a 32-byte hash");
  }
  if (rec.call.resultHash && !HASH_RE.test(rec.call.resultHash)) {
    errors.push("call.resultHash must be a 32-byte hash");
  }
  if (rec.outcome) {
    const statuses = new Set(["success", "failure", "denied", "timeout", "unknown"]);
    if (!statuses.has(rec.outcome.status)) {
      errors.push("outcome.status is not recognized");
    }
    if (!rec.outcome.completedAt) errors.push("outcome.completedAt is required");
    if (rec.outcome.resultHash) {
      if (!HASH_RE.test(rec.outcome.resultHash)) {
        errors.push("outcome.resultHash must be a 32-byte hash");
      }
      if (rec.call.resultHash && rec.outcome.resultHash !== rec.call.resultHash) {
        errors.push("outcome.resultHash must match call.resultHash");
      }
    }
  }
  return errors;
}
