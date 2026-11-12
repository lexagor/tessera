import { uuid } from "./crypto.js";
import { db } from "./db.js";
import type { Environment } from "./types.js";
import { emitWebhook } from "./webhooks.js";

export async function persistAction(
  environment: Environment & { broker_key_enc: string | null },
  response: Record<string, unknown>,
): Promise<void> {
  const receipt = response.receipt as Record<string, any>;
  const actionId = String(response.actionId || receipt.actionId || "");
  if (!actionId || !receipt) return;
  const authorization = receipt.authorization ?? {};
  const policy = receipt.policy ?? {};
  const credential = receipt.credential ?? {};
  const outcome = receipt.outcome ?? null;
  const createdAt = (receipt.ts as string) || new Date().toISOString();
  const inserted = await db()`
    INSERT INTO actions (
      action_id, org_id, environment_id, agent_id, principal_id, tool, decision,
      outcome_status, policy_id, policy_version, policy_hash, credential_issuer,
      credential_thumbprint, receipt_id, outcome_receipt_id, created_at, completed_at,
      verified, payload
    ) VALUES (
      ${actionId},
      ${environment.org_id},
      ${environment.id},
      ${String(receipt.agent ?? "")},
      ${String(receipt.principal?.principalId ?? receipt.user ?? "")},
      ${String(receipt.call?.tool ?? "")},
      ${String(authorization.decision ?? "deny")},
      ${outcome?.status ?? (authorization.decision === "deny" ? "denied" : null)},
      ${String(policy.policyId ?? authorization.policy ?? "")},
      ${Number(policy.policyVersion ?? authorization.policyVersion ?? 0)},
      ${policy.policyHash ?? null},
      ${credential.issuer ?? receipt.grant?.provider ?? null},
      ${credential.thumbprint ?? null},
      ${String(response.receiptId ?? "")},
      ${null},
      ${createdAt},
      ${outcome?.completedAt ?? null},
      ${null},
      ${db().json({ authorization: receipt, outcome: null } as never)}
    )
    ON CONFLICT (action_id) DO NOTHING
    RETURNING action_id
  `;
  if (inserted.length === 0) return;
  void emitWebhook(
    environment.org_id,
    authorization.decision === "deny" ? "action.denied" : "action.created",
    {
      actionId,
      environmentId: environment.id,
      agentId: String(receipt.agent ?? ""),
      principalId: String(receipt.principal?.principalId ?? receipt.user ?? ""),
      tool: String(receipt.call?.tool ?? ""),
      decision: String(authorization.decision ?? "deny"),
      receiptId: String(response.receiptId ?? ""),
      createdAt,
    },
  );
  await db()`
    INSERT INTO agents (id, environment_id, agent_id, last_seen_at)
    VALUES (${uuid()}, ${environment.id}, ${String(receipt.agent ?? "")}, now())
    ON CONFLICT (environment_id, agent_id) DO UPDATE SET last_seen_at = now()
  `;
  await db()`
    INSERT INTO usage_daily (org_id, environment_id, day, actions, allowed, denied)
    VALUES (
      ${environment.org_id}, ${environment.id}, current_date, 1,
      ${authorization.decision === "allow" ? 1 : 0},
      ${authorization.decision === "allow" ? 0 : 1}
    )
    ON CONFLICT (org_id, environment_id, day) DO UPDATE SET
      actions = usage_daily.actions + 1,
      allowed = usage_daily.allowed + EXCLUDED.allowed,
      denied = usage_daily.denied + EXCLUDED.denied
  `;
}

export async function persistOutcome(
  environment: Environment & { broker_key_enc: string | null },
  authorizationReceiptId: string,
  response: Record<string, unknown>,
): Promise<void> {
  const receipt = response.receipt as Record<string, any> | undefined;
  if (!receipt || response.status === "duplicate") return;
  const outcome = receipt.outcome ?? {};
  const updated = await db()`
    UPDATE actions
       SET outcome_status = ${outcome.status ?? null},
           outcome_receipt_id = ${String(response.receiptId ?? "")},
           completed_at = ${outcome.completedAt ?? null},
           payload = jsonb_set(payload, '{outcome}', ${db().json(receipt as never)})
     WHERE receipt_id = ${authorizationReceiptId}
       AND environment_id = ${environment.id}
    RETURNING action_id, agent_id, tool
  `;
  if (updated[0]) {
    void emitWebhook(environment.org_id, "action.completed", {
      actionId: updated[0].action_id as string,
      environmentId: environment.id,
      agentId: updated[0].agent_id as string,
      tool: updated[0].tool as string,
      outcomeStatus: String(outcome.status ?? "unknown"),
      outcomeReceiptId: String(response.receiptId ?? ""),
      completedAt: outcome.completedAt ?? new Date().toISOString(),
    });
  }
}
