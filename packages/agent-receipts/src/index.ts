import { createHash } from "node:crypto";

import { ed25519 } from "@noble/curves/ed25519";
import { canonicalize } from "@tessera-verify/receipt-schema";
import type { ReceiptV2 } from "@tessera-verify/receipt-schema";

export interface AgentReceiptProof {
  type: "Ed25519Signature2020";
  created: string;
  verificationMethod: string;
  proofPurpose: "assertionMethod";
  proofValue: string;
}

export interface AgentReceiptCredential {
  "@context": [string, string];
  id: string;
  type: ["VerifiableCredential", "AgentReceipt"];
  version: "0.5.0";
  issuer: {
    id: string;
    type: "AIAgent";
    name: string;
    operator: { id: string; name: string };
    model?: string;
    runtime?: { agent_id?: string; agent_type?: string };
  };
  issuanceDate: string;
  credentialSubject: {
    principal: { id: string; type: "HumanPrincipal" | "OrganizationPrincipal" };
    action: {
      id: string;
      type: string;
      risk_level: "low" | "medium" | "high" | "critical";
      target: { system: string; resource: string };
      timestamp: string;
      trusted_timestamp?: string;
    };
    outcome: {
      status: "success" | "failure" | "pending";
      error?: string;
    };
    authorization: {
      scopes: string[];
      granted_at: string;
      expires_at: string;
      grant_ref?: string;
    };
    chain: {
      chain_id: string;
      sequence: number;
      previous_receipt_hash: string | null;
    };
    tessera: {
      actionId: string;
      receiptId: string;
      previousReceiptId: string | null;
      signatureAlg: string;
    };
  };
  proof: AgentReceiptProof;
}

export interface ExportAgentReceiptInput {
  authorization: ReceiptV2;
  outcome?: ReceiptV2 | null;
  tenant: string;
  issuerDid: string;
  signingKey: string;
  sequence?: number;
  /** Reuse an issuance timestamp across a TSA request and the signed credential. */
  issuanceDate?: string;
  /** SHA-256 chain link when exporting a receipt that is not standalone. */
  previousReceiptHash?: string;
  /** Base64-encoded RFC 3161 TimeStampToken covering the canonical credential. */
  trustedTimestamp?: string;
}

const LOW_RISK = new Set([
  "filesystem.file.read",
  "data.api.read",
  "data.database.query",
  "system.browser.navigate",
]);

const MEDIUM_RISK = new Set([
  "filesystem.file.modify",
  "filesystem.file.move",
  "data.api.write",
  "document.file.modify",
  "unknown",
]);

const HIGH_RISK = new Set([
  "filesystem.file.delete",
  "data.api.delete",
  "data.database.modify",
  "communication.email.send",
  "communication.message.send",
]);

function actionType(tool: string): string {
  if (tool.includes("refund") || tool.includes("payment") || tool.includes("charge")) {
    return "financial.payment.initiate";
  }
  if (tool.includes("email")) return "communication.email.send";
  if (tool.includes("delete")) return "data.api.delete";
  if (tool.includes("read") || tool.includes("list") || tool.includes("get")) {
    return "data.api.read";
  }
  if (tool.includes("write") || tool.includes("create") || tool.includes("update")) {
    return "data.api.write";
  }
  return "unknown";
}

function riskLevel(tool: string, declared?: string | null): AgentReceiptCredential["credentialSubject"]["action"]["risk_level"] {
  if (declared === "low" || declared === "medium" || declared === "high" || declared === "critical") {
    return declared;
  }
  const type = actionType(tool);
  if (type.startsWith("financial.")) return "critical";
  if (HIGH_RISK.has(type)) return "high";
  if (MEDIUM_RISK.has(type)) return "medium";
  if (LOW_RISK.has(type)) return "low";
  return "high";
}

function sha256Hex(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function outcomeStatus(receipt: ReceiptV2): AgentReceiptCredential["credentialSubject"]["outcome"] {
  const outcome = receipt.outcome;
  if (!outcome) return { status: "pending" };
  if (outcome.status === "success") return { status: "success" };
  return {
    status: "failure",
    ...(outcome.errorClass ? { error: outcome.errorClass } : {}),
  };
}

function proofValue(signature: Uint8Array): string {
  return `u${Buffer.from(signature).toString("base64url")}`;
}

export function buildAgentReceipt(
  input: Omit<ExportAgentReceiptInput, "signingKey">,
): AgentReceiptCredential {
  const { authorization, outcome, tenant } = input;
  const receipt = outcome ?? authorization;
  if (!receipt.actionId || !receipt.principal || !receipt.agentMeta) {
    throw new Error("agent receipt export requires a v2 action record");
  }
  const tool = receipt.call.tool;
  const type = actionType(tool);
  const now = input.issuanceDate ?? new Date().toISOString();
  const issuedAt = authorization.ts;
  const expiresAt = new Date(
    Date.parse(issuedAt) + authorization.grant.ttlS * 1000,
  ).toISOString();
  const nativePrevious = authorization.prev ?? null;
  const chainId = `${tenant}:${receipt.agent}`;
  return {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://agentreceipts.ai/context/v2",
    ],
    id: `urn:receipt:${receipt.actionId}`,
    type: ["VerifiableCredential", "AgentReceipt"],
    version: "0.5.0",
    issuer: {
      id: input.issuerDid,
      type: "AIAgent",
      name: receipt.agentMeta.agentId,
      operator: { id: input.issuerDid, name: "Tessera" },
      ...(receipt.agentMeta.modelId ? { model: receipt.agentMeta.modelId } : {}),
      runtime: {
        agent_id: receipt.agentMeta.agentId,
        ...(receipt.agentMeta.environment
          ? { agent_type: receipt.agentMeta.environment }
          : {}),
      },
    },
    issuanceDate: now,
    credentialSubject: {
      principal: {
        id: receipt.principal.principalId.startsWith("did:")
          ? receipt.principal.principalId
          : `did:user:${receipt.principal.principalId}`,
        type: "HumanPrincipal",
      },
      action: {
        id: `act_${receipt.actionId}`,
        type,
        risk_level: riskLevel(tool, receipt.intent?.riskClass),
        target: {
          system: receipt.authorization.resource.split(":")[0] ?? "unknown",
          resource: receipt.authorization.resource,
        },
        timestamp: receipt.ts,
        ...(input.trustedTimestamp
          ? { trusted_timestamp: input.trustedTimestamp }
          : {}),
      },
      outcome: outcomeStatus(receipt),
      authorization: {
        scopes: receipt.credential?.scopes ?? [],
        granted_at: issuedAt,
        expires_at: expiresAt,
        ...(receipt.credential?.issuanceId
          ? { grant_ref: receipt.credential.issuanceId }
          : {}),
      },
      chain: {
        chain_id: chainId,
        sequence: input.sequence ?? 1,
        previous_receipt_hash: input.previousReceiptHash ?? null,
      },
      tessera: {
        actionId: receipt.actionId,
        receiptId: `sha256:${sha256Hex(canonicalize(receipt))}`,
        previousReceiptId: nativePrevious,
        signatureAlg: receipt.attestation?.signatureAlg ?? "secp256k1-eip712",
      },
    },
    proof: {
      type: "Ed25519Signature2020",
      created: now,
      verificationMethod: `${input.issuerDid}#key-1`,
      proofPurpose: "assertionMethod",
      proofValue: "",
    },
  };
}

export function canonicalAgentReceipt(credential: AgentReceiptCredential): string {
  const unsigned = { ...credential, proof: undefined };
  return canonicalize(unsigned);
}

export function signAgentReceipt(
  credential: AgentReceiptCredential,
  signingKey: string,
): AgentReceiptCredential {
  const key = Buffer.from(signingKey.replace(/^0x/, ""), "hex");
  if (key.length !== 32) {
    throw new Error("agent receipt signingKey must be a 32-byte hex seed");
  }
  const signature = ed25519.sign(
    new TextEncoder().encode(canonicalAgentReceipt(credential)),
    key,
  );
  return {
    ...credential,
    proof: { ...credential.proof, proofValue: proofValue(signature) },
  };
}

export function exportAgentReceipt(input: ExportAgentReceiptInput): AgentReceiptCredential {
  return signAgentReceipt(buildAgentReceipt(input), input.signingKey);
}

export function verifyAgentReceiptSignature(
  credential: AgentReceiptCredential,
  publicKey: Uint8Array,
): boolean {
  const encoded = credential.proof.proofValue.replace(/^u/, "");
  const signature = Buffer.from(encoded, "base64url");
  return ed25519.verify(
    signature,
    new TextEncoder().encode(canonicalAgentReceipt(credential)),
    publicKey,
  );
}

export { requestTrustedTimestamp } from "./timestamp.js";
