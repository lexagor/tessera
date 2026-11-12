/**
 * Canonical policy model, shared by the control plane, the broker, and the SDKs.
 *
 * A policy binds a declared intent scope to a capability bound for a resource.
 * Evaluation is expressed in CEL; this module defines the shape and the helpers.
 */

export interface IntentScope {
  /** Free-form description used for intent matching / embeddings. */
  description: string;
  /** Optional structured action list (e.g. ["read", "write"]). */
  actions?: string[];
}

export interface ResourceGrant {
  /** e.g. "stripe:charge", "github:repo:write", "s3:object:get". */
  resource: string;
  /** CEL expression over the request context. */
  condition?: string;
  /** Allowed argument constraints (allowlist, max amount, path prefixes). */
  constraints?: Record<string, unknown>;
}

export interface Policy {
  id: string;
  version: number;
  name: string;
  description?: string;
  intent: IntentScope;
  grants: ResourceGrant[];
  /** Default deny; set true only for explicitly non-sensitive read-only resources. */
  failOpen?: boolean;
}

export interface PolicyContext {
  agentId: string;
  userId: string;
  tool: string;
  args: Record<string, unknown>;
  resource: string;
}

export interface PolicyResult {
  allow: boolean;
  matched?: ResourceGrant;
  reason: string;
}

/**
 * Reference evaluator. TODO: delegate to a Rust CEL runtime in the broker and keep
 * this as the shared TypeScript implementation for the control plane / SDK.
 */
export function evaluatePolicy(policy: Policy, ctx: PolicyContext): PolicyResult {
  const grant = policy.grants.find((g) => g.resource === ctx.resource);
  if (!grant) return { allow: false, reason: `no grant for ${ctx.resource}` };
  return { allow: true, matched: grant, reason: "grant matched (conditions not yet evaluated)" };
}
