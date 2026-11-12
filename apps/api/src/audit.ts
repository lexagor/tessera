import { uuid } from "./crypto.js";
import { db } from "./db.js";

export async function audit(input: {
  orgId: string;
  actorUserId?: string | null;
  actorType?: string;
  action: string;
  target?: string | null;
  details?: Record<string, unknown>;
}): Promise<void> {
  await db()`
    INSERT INTO audit_log (id, org_id, actor_user_id, actor_type, action, target, details)
    VALUES (
      ${uuid()},
      ${input.orgId},
      ${input.actorUserId ?? null},
      ${input.actorType ?? "user"},
      ${input.action},
      ${input.target ?? null},
      ${db().json((input.details ?? {}) as never)}
    )
  `;
}
