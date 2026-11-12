import { canonicalize, keccak256Hex } from "@tessera/receipt-schema";

import { createClient, TesseraClient } from "./client.js";
import type {
  AuthorizeInput,
  EphemeralCredential,
  ProxyRequest,
  ProxyResponse,
  TesseraConfig,
} from "./types.js";

/**
 * The adapter that actually invokes the provider. It receives the ephemeral credential
 * explicitly, so it can configure the provider client for this one call (Stripe key,
 * GitHub token, AWS session, ...). The SDK never assumes a provider's argument shape.
 */
export type ToolRunner<T> = (
  args: Record<string, unknown>,
  credential: EphemeralCredential,
  options?: WrapOptions,
) => Promise<T>;

/** Per-invocation options for wrapped tools. */
export interface WrapOptions {
  /** Override the generated idempotency key (e.g. to make a retry explicit). */
  idempotencyKey?: string;
}

function defaultIdempotencyKey(): string {
  const cryptoApi = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto;
  if (cryptoApi?.randomUUID) return cryptoApi.randomUUID();
  return `tessera-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

/**
 * Wrap a tool invocation so each call is brokered:
 *   1. authorize with the declared intent + args,
 *   2. run the provider call with the ephemeral credential,
 *   3. record the outcome.
 *
 * The `run` adapter is where you bind the credential to the provider client. This keeps
 * the SDK provider-agnostic instead of pretending every client accepts a credential
 * argument.
 *
 * Usage:
 *   const refund = wrapFn(
 *     tessera,
 *     { tool: "stripe.refunds.create", intent: "refund a duplicate charge" },
 *     (args, credential) => stripe.refunds.create(args, { apiKey: credential.material.token }),
 *   );
 *   await refund({ charge: "ch_123", amount: 4200 });
 */
export function wrapFn<T>(
  client: TesseraClient,
  meta: {
    tool: string;
    intent: string;
    toolSchemaHash?: string;
    principal?: AuthorizeInput["principal"];
    agentMeta?: AuthorizeInput["agentMeta"];
    requestedScopes?: string[];
    riskClass?: string;
    declaredPurpose?: string;
    authorityToken?: string;
  },
  run: ToolRunner<T>,
): (args: Record<string, unknown>, options?: WrapOptions) => Promise<T> {
  return async (args, options) => {
    const input: AuthorizeInput = {
      tool: meta.tool,
      intent: meta.intent,
      args,
      ...(meta.toolSchemaHash ? { toolSchemaHash: meta.toolSchemaHash } : {}),
      ...(meta.principal ? { principal: meta.principal } : {}),
      ...(meta.agentMeta ? { agentMeta: meta.agentMeta } : {}),
      ...(meta.requestedScopes ? { requestedScopes: meta.requestedScopes } : {}),
      ...(meta.riskClass ? { riskClass: meta.riskClass } : {}),
      ...(meta.declaredPurpose ? { declaredPurpose: meta.declaredPurpose } : {}),
      ...(meta.authorityToken ? { authorityToken: meta.authorityToken } : {}),
    };
    // One idempotency key per invocation covers authorize + record, so a retried
    // invocation cannot mint a second credential or duplicate the outcome receipt.
    const idempotencyKey = options?.idempotencyKey ?? defaultIdempotencyKey();
    const result = await client.authorize(input, { idempotencyKey });
    if (result.decision !== "allow" || !result.credential) {
      throw new Error("tessera: authorization denied");
    }
    const credential: EphemeralCredential = result.credential;
    const brokerObservable = credential.material.kind === "grant";
    try {
      const out = await run(args, credential, { idempotencyKey });
      if (!brokerObservable) {
        await client.record(
          { receiptId: result.receiptId, resultHash: hashResult(out), status: "success" },
          { idempotencyKey },
        );
      }
      return out;
    } catch (err) {
      if (!brokerObservable) {
        await client.record(
          {
            receiptId: result.receiptId,
            resultHash: hashResult({ error: String(err) }),
            status: "failure",
            errorClass: err instanceof Error ? err.name : "Error",
          },
          { idempotencyKey },
        );
      }
      throw err;
    }
  };
}

/**
 * Wrap a broker-held grant (Stripe-style). The provider secret never reaches the agent;
 * the broker redeems the grant and forwards the request.
 */
export function wrapProxy(
  client: TesseraClient,
  meta: { tool: string; intent: string; toolSchemaHash?: string },
  request: Omit<ProxyRequest, "grantId" | "argsHash">,
): (args: Record<string, unknown>, options?: WrapOptions) => Promise<ProxyResponse> {
  return wrapFn<ProxyResponse>(client, meta, async (_args, credential, options) => {
    if (credential.material.kind !== "grant") {
      throw new Error("tessera: wrapProxy requires a broker-held grant credential");
    }
    return client.proxy(
      {
        ...request,
        grantId: credential.material.grantId,
        argsHash: credential.argsHash,
      },
      { idempotencyKey: options?.idempotencyKey },
    );
  });
}

/** Convenience factory bound to a config. */
export function wrap<T>(
  config: TesseraConfig,
  tool: string,
  intent: string,
  run: ToolRunner<T>,
) {
  return wrapFn(createClient(config), { tool, intent }, run);
}

/** Canonical, cross-language result hash (matches the broker's canonical form). */
export function hashResult(value: unknown): string {
  return keccak256Hex(canonicalize(value));
}
