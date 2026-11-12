import type {
  AnchorBatch,
  AuthorizeInput,
  AuthorizeResult,
  ChainVerification,
  ProposedPolicy,
  ProxyRequest,
  ProxyResponse,
  ReceiptVerification,
  RecordInput,
  RevokeOutcome,
  TesseraConfig,
} from "./types.js";

/** Per-call options shared by the mutating endpoints. */
export interface CallOptions {
  /**
   * Idempotency key: retries with the same key return the original response and never
   * issue a second credential, write a second receipt, or call the provider twice.
   * Generate one per logical operation (e.g. `crypto.randomUUID()`).
   */
  idempotencyKey?: string;
}

/**
 * Client for the Tessera broker. Provides `authorize`/`record` and a `wrap` helper
 * that transparently brokers an ephemeral credential before a tool call.
 */
export class TesseraClient {
  constructor(private readonly config: TesseraConfig) {}

  private mutationHeaders(options?: CallOptions): Record<string, string> {
    const headers: Record<string, string> = {
      "content-type": "application/json",
      authorization: `Bearer ${this.config.apiKey}`,
    };
    if (options?.idempotencyKey) {
      headers["idempotency-key"] = options.idempotencyKey;
    }
    return headers;
  }

  async authorize(input: AuthorizeInput, options?: CallOptions): Promise<AuthorizeResult> {
    const principal = input.principal ?? this.config.principal;
    const agentMeta = input.agentMeta ?? this.config.agentMeta;
    const authorityToken = input.authorityToken ?? this.config.authorityToken;
    const res = await fetch(`${this.config.endpoint}/v1/authorize`, {
      method: "POST",
      headers: this.mutationHeaders(options),
      body: JSON.stringify({
        agentId: this.config.agentId,
        userId: this.config.userId,
        tool: input.tool,
        intent: input.intent,
        args: input.args,
        ...(input.toolSchemaHash ? { toolSchemaHash: input.toolSchemaHash } : {}),
        ...(principal ? { principal } : {}),
        ...(agentMeta ? { agentMeta } : {}),
        ...(input.requestedScopes ? { requestedScopes: input.requestedScopes } : {}),
        ...(input.riskClass ? { riskClass: input.riskClass } : {}),
        ...(input.declaredPurpose ? { declaredPurpose: input.declaredPurpose } : {}),
        ...(authorityToken ? { authorityToken } : {}),
      }),
    });
    if (!res.ok) throw new Error(`tessera authorize failed: ${res.status}`);
    return (await res.json()) as AuthorizeResult;
  }

  async record(input: RecordInput, options?: CallOptions): Promise<void> {
    const res = await fetch(`${this.config.endpoint}/v1/record`, {
      method: "POST",
      headers: this.mutationHeaders(options),
      body: JSON.stringify({
        agentId: this.config.agentId,
        receiptId: input.receiptId,
        resultHash: input.resultHash,
        ...(input.status ? { status: input.status } : {}),
        ...(input.errorClass ? { errorClass: input.errorClass } : {}),
        ...(input.externalRef ? { externalRef: input.externalRef } : {}),
        ...(input.completedAt ? { completedAt: input.completedAt } : {}),
      }),
    });
    if (!res.ok) throw new Error(`tessera record failed: ${res.status}`);
  }

  /**
   * Redeem a broker-held grant and forward one request to the provider.
   * Use this when `credential.material.kind === "grant"`.
   */
  async proxy(req: ProxyRequest, options?: CallOptions): Promise<ProxyResponse> {
    const res = await fetch(`${this.config.endpoint}/v1/proxy`, {
      method: "POST",
      headers: this.mutationHeaders(options),
      body: JSON.stringify(req),
    });
    if (!res.ok) throw new Error(`tessera proxy failed: ${res.status}`);
    return (await res.json()) as ProxyResponse;
  }

  /** Build the Merkle anchor batch (root + calldata) for an agent's current chain. */
  async anchor(agentId: string): Promise<AnchorBatch> {
    const res = await fetch(
      `${this.config.endpoint}/v1/chain/${encodeURIComponent(agentId)}/anchor`,
      { headers: { authorization: `Bearer ${this.config.apiKey}` } },
    );
    if (!res.ok) throw new Error(`tessera anchor failed: ${res.status}`);
    return (await res.json()) as AnchorBatch;
  }

  /** Submit the agent's current chain root to the on-chain anchor contract. */
  async submitAnchor(agentId: string): Promise<{ status: string; txHash: string }> {
    const res = await fetch(
      `${this.config.endpoint}/v1/chain/${encodeURIComponent(agentId)}/anchor/submit`,
      {
        method: "POST",
        headers: { authorization: `Bearer ${this.config.apiKey}` },
      },
    );
    if (!res.ok) throw new Error(`tessera anchor submit failed: ${res.status}`);
    return await res.json();
  }

  /** Propose a least-privilege policy from the tenant's telemetry graph. */
  async proposePolicy(): Promise<ProposedPolicy> {
    const res = await fetch(`${this.config.endpoint}/v1/policies/propose`, {
      headers: { authorization: `Bearer ${this.config.apiKey}` },
    });
    if (!res.ok) throw new Error(`tessera propose failed: ${res.status}`);
    const body = await res.json();
    return { policy: body.policy, evidence: body.evidence, notes: body.notes };
  }

  /** Revoke an agent, a grant, or an issued credential (provider-native where supported). */
  async revoke(
    target: string,
    kind: "grant" | "agent" | "credential" = "grant",
    reason?: string,
  ): Promise<RevokeOutcome> {
    const res = await fetch(`${this.config.endpoint}/v1/revoke`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${this.config.apiKey}`,
      },
      body: JSON.stringify({ target, kind, reason }),
    });
    if (!res.ok) throw new Error(`tessera revoke failed: ${res.status}`);
    return (await res.json()) as RevokeOutcome;
  }

  /** Verify a receipt independently (no broker trust required). */
  async verifyReceipt(receipt: Record<string, unknown>): Promise<ReceiptVerification> {
    const res = await fetch(`${this.config.endpoint}/v1/verify/receipt`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(receipt),
    });
    if (!res.ok) throw new Error(`tessera verify failed: ${res.status}`);
    return (await res.json()) as ReceiptVerification;
  }

  /** Verify a chain independently. */
  async verifyChain(entries: unknown[]): Promise<ChainVerification> {
    const res = await fetch(`${this.config.endpoint}/v1/verify/chain`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ entries }),
    });
    if (!res.ok) throw new Error(`tessera verify failed: ${res.status}`);
    return (await res.json()) as ChainVerification;
  }
}

export function createClient(config: TesseraConfig): TesseraClient {
  return new TesseraClient(config);
}
