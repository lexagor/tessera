import type { AnyReceipt } from "@tessera-verify/receipt-schema";

export interface TrustEntity {
  id: string;
  label: string;
  title: string;
  detail: string;
  hash?: string;
  state: "valid" | "warning" | "invalid" | "missing";
}

export interface TrustView {
  entities: TrustEntity[];
  summary: string;
  decision: string;
  outcome: string;
}

type LooseReceipt = Record<string, any>;

export function extractRecords(body: LooseReceipt): {
  authorization?: LooseReceipt;
  outcome?: LooseReceipt | null;
  chainLength?: number;
} {
  if (Array.isArray(body.entries)) {
    const entries = body.entries as Array<{ receipt?: LooseReceipt }>;
    return {
      authorization: entries.at(-1)?.receipt,
      outcome: null,
      chainLength: entries.length,
    };
  }
  if (body.authorization) {
    return { authorization: body.authorization, outcome: body.outcome ?? null };
  }
  if (body.receipt) {
    return { authorization: body.receipt, outcome: null };
  }
  if (typeof body.v === "number") {
    return { authorization: body, outcome: null };
  }
  return {};
}

export function buildTrustView(input: {
  authorization?: LooseReceipt | null;
  outcome?: LooseReceipt | null;
  chainLength?: number;
  verification?: { valid: boolean; recovered?: string };
  signer?: string | null;
}): TrustView {
  const authorization = input.authorization ?? {};
  const outcome = input.outcome ?? {};
  const principal = authorization.principal ?? {};
  const intent = authorization.intent ?? {};
  const policy = authorization.policy ?? {};
  const agentMeta = authorization.agentMeta ?? {};
  const call = authorization.call ?? {};
  const credential = authorization.credential ?? {};
  const outcomeRef = outcome.outcome ?? {};
  const attestation = authorization.attestation ?? {};
  const valid = input.verification?.valid === true;
  const entities: TrustEntity[] = [
    {
      id: "human",
      label: "Human",
      title: String(principal.principalId ?? authorization.user ?? "Unknown principal"),
      detail: `${principal.principalType ?? "user"} · ${principal.verificationMethod ?? "caller-asserted"}`,
      hash: principal.authorityHash,
      state: principal.principalId || authorization.user ? "valid" : "missing",
    },
    {
      id: "intent",
      label: "Intent",
      title: String(intent.declaredPurpose ?? "Declared tool intent"),
      detail: intent.riskClass ? `Risk class: ${intent.riskClass}` : "Intent hash bound to the record",
      hash: intent.intentHash ?? authorization.intentHash,
      state: intent.intentHash || authorization.intentHash ? "valid" : "warning",
    },
    {
      id: "policy",
      label: "Policy",
      title: `${policy.policyId ?? authorization.authorization?.policy ?? "No policy"}${policy.policyVersion ? ` v${policy.policyVersion}` : ""}`,
      detail: String(authorization.authorization?.reasonCode ?? authorization.authorization?.decision ?? "Policy decision recorded"),
      hash: policy.policyHash,
      state: policy.policyHash ? "valid" : "warning",
    },
    {
      id: "agent",
      label: "Agent",
      title: String(authorization.agent ?? "Unknown agent"),
      detail: agentMeta.agentVersion
        ? `v${agentMeta.agentVersion}${agentMeta.modelId ? ` · ${agentMeta.modelId}` : ""}`
        : "Agent identity recorded",
      state: authorization.agent ? "valid" : "missing",
    },
    {
      id: "tool",
      label: "Tool",
      title: String(call.tool ?? "Unknown tool"),
      detail: `Arguments hash ${String(call.argsHash ?? "—")}`,
      hash: call.argsHash,
      state: call.tool && call.argsHash ? "valid" : "missing",
    },
    {
      id: "credential",
      label: "Credential",
      title: String(credential.credentialType ?? credential.issuer ?? "No credential"),
      detail: [
        credential.issuer ? `Issuer ${credential.issuer}` : null,
        credential.ttlSeconds ? `${credential.ttlSeconds}s TTL` : null,
        credential.singleUse ? "single use" : null,
      ].filter(Boolean).join(" · ") || "Credential binding recorded",
      hash: credential.thumbprint,
      state: credential.thumbprint || credential.issuer ? "valid" : "warning",
    },
    {
      id: "outcome",
      label: "Outcome",
      title: String(outcomeRef.status ?? "Not recorded"),
      detail: String(outcomeRef.source ?? "No provenance"),
      hash: outcomeRef.resultHash,
      state: outcomeRef.status ? (outcomeRef.source ? "valid" : "warning") : "missing",
    },
    {
      id: "signature",
      label: "Signature",
      title: valid ? "Signature valid" : "Signature invalid",
      detail: input.signer || input.verification?.recovered || attestation.signerKeyId || "Signer unavailable",
      hash: attestation.signerKeyId,
      state: valid ? "valid" : "invalid",
    },
  ];
  if (input.chainLength !== undefined) {
    entities.push({
      id: "chain",
      label: "Chain",
      title: `${input.chainLength} linked record${input.chainLength === 1 ? "" : "s"}`,
      detail: "Each record binds the previous payload hash.",
      state: input.chainLength > 0 ? "valid" : "missing",
    });
  }
  const decision = String(authorization.authorization?.decision ?? "unknown");
  const outcomeStatus = String(outcomeRef.status ?? "not recorded");
  return {
    entities,
    summary: `${entities[3]?.title ?? "The agent"} acted for ${entities[0]?.title ?? "a principal"} through ${entities[4]?.title ?? "a tool"}.`,
    decision,
    outcome: outcomeStatus,
  };
}

/** Mutate a signed field while preserving the rest of the record, for the browser tamper demo. */
export function tamperPayload(body: LooseReceipt): LooseReceipt {
  const copy = structuredClone(body) as LooseReceipt;
  if (Array.isArray(copy.entries) && copy.entries.length) {
    const receipt = copy.entries[copy.entries.length - 1]?.receipt;
    if (receipt?.call) receipt.call.tool = `${receipt.call.tool} (tampered)`;
    else if (receipt?.agent) receipt.agent = `${receipt.agent}-tampered`;
    return copy;
  }
  const receipt = copy.authorization ?? copy.receipt ?? copy;
  if (receipt?.call?.tool) {
    receipt.call.tool = `${receipt.call.tool} (tampered)`;
  } else if (receipt?.authorization?.policy) {
    receipt.authorization.policy = `${receipt.authorization.policy}-tampered`;
  } else if (receipt?.agent) {
    receipt.agent = `${receipt.agent}-tampered`;
  } else if (receipt?.v === 2) {
    receipt.tenant = `${receipt.tenant}-tampered`;
  }
  return copy;
}

export function receiptBytes(receipt: AnyReceipt | LooseReceipt): number {
  return new Blob([JSON.stringify(receipt)]).size;
}
