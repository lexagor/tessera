import * as broker from "./broker.js";
import { db } from "./db.js";
import type { Environment } from "./types.js";

export const FRAMEWORK_IDS = ["soc2", "iso42001", "eu-ai-act", "nist-ai-rmf", "dora"] as const;
export type FrameworkId = (typeof FRAMEWORK_IDS)[number];
type CoverageStatus = "covered" | "partial" | "gap";

export interface EvidenceFilters {
  frameworks: FrameworkId[];
  since: string;
  until: string;
  agentId: string | null;
  recipients: string[];
}

export interface EvidenceFilterInput {
  frameworks?: unknown;
  since?: unknown;
  until?: unknown;
  agentId?: unknown;
  recipients?: unknown;
}

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
  id: string;
  title: string;
  question: string;
  evidence: string[];
}

export interface EvidenceFramework {
  id: FrameworkId;
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

export interface EvidencePackSummary {
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
  transitions: Array<{
    id: string;
    kind: string;
    target: string;
    at: string;
    eventHash: string;
  }>;
  verificationLinks: Array<{
    id: string;
    actionId: string;
    createdAt: string;
    expiresAt: string;
  }>;
  proof: {
    chainsVerified: boolean | null;
    keyEventsVerified: boolean | null;
    chainReceipts: number;
    anchors: number;
    anchorLatest: string | null;
    unanchoredAgents: number;
  };
}

interface ControlDefinition {
  id: string;
  title: string;
  question: string;
  evidence: string[];
}

interface FrameworkDefinition {
  id: FrameworkId;
  name: string;
  description: string;
  controls: ControlDefinition[];
}

const FRAMEWORKS: FrameworkDefinition[] = [
  {
    id: "soc2",
    name: "SOC 2",
    description: "Security, availability, and processing integrity evidence.",
    controls: [
      {
        id: "CC6.1",
        title: "Logical access",
        question: "Is every action tied to a named principal and an evaluated policy?",
        evidence: ["principal", "policy"],
      },
      {
        id: "CC7.2",
        title: "System monitoring",
        question: "Are agent actions and outcomes recorded and independently verified?",
        evidence: ["actions", "verified"],
      },
      {
        id: "CC7.3",
        title: "Incident evaluation",
        question: "Can risky actions be reviewed by a human before they complete?",
        evidence: ["reviews", "provenance"],
      },
      {
        id: "CC7.4",
        title: "Incident response",
        question: "Can authority be revoked or narrowed after an incident?",
        evidence: ["denied", "transitions"],
      },
      {
        id: "CC8.1",
        title: "Change management",
        question: "Are policy changes signed and recorded?",
        evidence: ["policy", "policy_changes"],
      },
    ],
  },
  {
    id: "iso42001",
    name: "ISO 42001",
    description: "AI management system evidence for operation, verification, and response.",
    controls: [
      {
        id: "A.6.2.2",
        title: "AI risk assessment",
        question: "Are policy boundaries and blocked actions visible in the record?",
        evidence: ["policy", "denied"],
      },
      {
        id: "A.6.2.4",
        title: "AI system verification",
        question: "Can an independent verifier check the signed action record?",
        evidence: ["verified", "provenance"],
      },
      {
        id: "A.6.2.6",
        title: "Operation and monitoring",
        question: "Are agent actions and human reviews recorded in one trace?",
        evidence: ["actions", "reviews"],
      },
      {
        id: "A.8.2",
        title: "AI incident management",
        question: "Are outcome provenance and authority transitions retained?",
        evidence: ["provenance", "transitions"],
      },
    ],
  },
  {
    id: "eu-ai-act",
    name: "EU AI Act",
    description: "Record-keeping and human-oversight evidence for high-risk systems.",
    controls: [
      {
        id: "Art. 12",
        title: "Record-keeping",
        question: "Does the log retain signed actions, outcomes, and a tamper-evident anchor?",
        evidence: ["actions", "verified", "anchors"],
      },
      {
        id: "Art. 26",
        title: "Human oversight",
        question: "Can a human see the principal, policy, and review decision?",
        evidence: ["principal", "reviews"],
      },
    ],
  },
  {
    id: "nist-ai-rmf",
    name: "NIST AI RMF",
    description: "Govern, map, measure, and manage evidence across the AI lifecycle.",
    controls: [
      {
        id: "GOVERN 1.1",
        title: "Policies and procedures",
        question: "Are policies versioned and are changes recorded?",
        evidence: ["policy", "policy_changes"],
      },
      {
        id: "MAP 5.1",
        title: "Likelihood and impact",
        question: "Are risky or blocked actions identifiable for review?",
        evidence: ["denied", "reviews"],
      },
      {
        id: "MEASURE 2.6",
        title: "Performance monitoring",
        question: "Are outcomes recorded with provenance and verification?",
        evidence: ["actions", "provenance", "verified"],
      },
      {
        id: "MANAGE 2.2",
        title: "Response and recovery",
        question: "Can credentials be revoked or rotated with a signed record?",
        evidence: ["transitions", "credentials"],
      },
    ],
  },
  {
    id: "dora",
    name: "DORA",
    description: "ICT protection and incident-logging evidence for financial operators.",
    controls: [
      {
        id: "Art. 9",
        title: "Protection and prevention",
        question: "Are agent credentials and policy boundaries scoped per environment?",
        evidence: ["policy", "credentials"],
      },
      {
        id: "Art. 17",
        title: "ICT incident management",
        question: "Are failures, blocked actions, and reviews logged with provenance?",
        evidence: ["provenance", "reviews"],
      },
    ],
  },
];

function parseDate(value: unknown, fallback: Date, endOfDay = false): Date {
  if (typeof value !== "string" || !value.trim()) return fallback;
  const trimmed = value.trim();
  const dateOnly = /^\d{4}-\d{2}-\d{2}$/.test(trimmed);
  const date = new Date(dateOnly ? `${trimmed}T${endOfDay ? "23:59:59.999" : "00:00:00.000"}Z` : trimmed);
  if (Number.isNaN(date.getTime())) throw new Error(`Invalid date: ${trimmed}`);
  return date;
}

export function normalizeEvidenceFilters(input: unknown, now = new Date()): EvidenceFilters {
  const raw = input && typeof input === "object" ? (input as EvidenceFilterInput) : {};
  const requested = Array.isArray(raw.frameworks)
    ? raw.frameworks.filter((value): value is FrameworkId =>
        FRAMEWORK_IDS.includes(value as FrameworkId),
      )
    : [];
  const frameworks = requested.length ? [...new Set(requested)] : [...FRAMEWORK_IDS];
  const defaultSince = new Date(now.getTime() - 30 * 86_400_000);
  const since = parseDate(raw.since, defaultSince);
  const until = parseDate(raw.until, now, true);
  if (since > until) throw new Error("since must be before until");
  if (until.getTime() - since.getTime() > 366 * 86_400_000) {
    throw new Error("date range must be 366 days or less");
  }
  const agentId =
    typeof raw.agentId === "string" && raw.agentId.trim()
      ? raw.agentId.trim().slice(0, 128)
      : null;
  const recipients = Array.isArray(raw.recipients)
    ? raw.recipients
        .filter((value): value is string => typeof value === "string" && value.trim().length > 0)
        .map((value) => value.trim().slice(0, 254))
        .slice(0, 10)
    : [];
  return {
    frameworks,
    since: since.toISOString(),
    until: until.toISOString(),
    agentId,
    recipients,
  };
}

function statusFor(value: number, total: number, threshold = 0.95): CoverageStatus {
  if (total <= 0 || value <= 0) return "gap";
  return value / total >= threshold ? "covered" : "partial";
}

function signal(
  id: string,
  label: string,
  value: number,
  total: number,
  detail: string,
  options: { status?: CoverageStatus; gap?: string } = {},
): EvidenceSignal {
  return {
    id,
    label,
    value,
    total,
    status: options.status ?? statusFor(value, total),
    detail,
    gap: options.gap,
  };
}

function asDate(value: unknown): string {
  if (typeof value === "string" || value instanceof Date) {
    const date = new Date(value);
    if (!Number.isNaN(date.getTime())) return date.toISOString();
  }
  return "";
}

function within(value: string, since: string, until: string): boolean {
  return Boolean(value) && value >= since && value <= until;
}

function isTransition(item: Record<string, any>): boolean {
  return Boolean(item.details?.transitionType) || String(item.kind ?? "").startsWith("authority.");
}

export async function buildEvidenceSummary(
  orgName: string,
  environment: Environment & { broker_key_enc?: string | null },
  filters: EvidenceFilters,
  options: { plannedPack?: boolean } = {},
): Promise<EvidencePackSummary> {
  const agentId = filters.agentId;
  const actionRows = await db()`
    SELECT count(*)::int AS total,
           count(*) FILTER (WHERE decision = 'allow')::int AS allowed,
           count(*) FILTER (WHERE decision = 'deny')::int AS denied,
           count(*) FILTER (WHERE outcome_status IN ('success', 'failure', 'timeout'))::int AS completed,
           count(*) FILTER (WHERE outcome_status = 'failure')::int AS failed,
           count(*) FILTER (WHERE principal_id IS NOT NULL AND principal_id <> '')::int AS with_principal,
           count(*) FILTER (WHERE policy_id IS NOT NULL AND policy_id <> '')::int AS with_policy,
           count(*) FILTER (WHERE verified IS TRUE)::int AS verified,
           count(*) FILTER (WHERE payload->'outcome'->'outcome'->>'source' IS NOT NULL)::int AS with_provenance,
           count(*) FILTER (WHERE payload->'outcome'->'outcome'->>'source' = 'broker_observed')::int AS broker_observed,
           count(DISTINCT agent_id)::int AS agents,
           count(DISTINCT policy_id) FILTER (WHERE policy_id IS NOT NULL AND policy_id <> '')::int AS policy_count
      FROM actions
     WHERE org_id = ${environment.org_id}
       AND environment_id = ${environment.id}
       AND created_at >= ${filters.since}
       AND created_at <= ${filters.until}
       AND (${agentId}::text IS NULL OR agent_id = ${agentId})
  `;
  const stats = (actionRows[0] ?? {}) as Record<string, number>;

  const reviewRows = await db()`
    SELECT count(*)::int AS total,
           count(*) FILTER (WHERE r.status = 'pending')::int AS pending,
           count(*) FILTER (WHERE r.status = 'approved')::int AS approved,
           count(*) FILTER (WHERE r.status = 'rejected')::int AS rejected
      FROM action_reviews r
      JOIN actions a ON a.action_id = r.action_id
     WHERE r.org_id = ${environment.org_id}
       AND r.environment_id = ${environment.id}
       AND a.created_at >= ${filters.since}
       AND a.created_at <= ${filters.until}
       AND (${agentId}::text IS NULL OR a.agent_id = ${agentId})
  `;
  const reviewStats = (reviewRows[0] ?? {}) as Record<string, number>;

  const reviewItems = await db()`
    SELECT r.id, r.action_id, r.status, r.reason, r.resolution_note, r.created_at, r.resolved_at
      FROM action_reviews r
      JOIN actions a ON a.action_id = r.action_id
     WHERE r.org_id = ${environment.org_id}
       AND r.environment_id = ${environment.id}
       AND a.created_at >= ${filters.since}
       AND a.created_at <= ${filters.until}
       AND (${agentId}::text IS NULL OR a.agent_id = ${agentId})
     ORDER BY r.created_at DESC LIMIT 20
  `;

  const linkRows = await db()`
    SELECT id, action_id, created_at, expires_at
      FROM verification_links
     WHERE org_id = ${environment.org_id}
       AND environment_id = ${environment.id}
       AND created_at >= ${filters.since}
       AND created_at <= ${filters.until}
       AND revoked_at IS NULL
     ORDER BY created_at DESC LIMIT 100
  `;

  const keyRows = await db()`
    SELECT count(*)::int AS active
      FROM agent_keys
     WHERE environment_id = ${environment.id}
       AND revoked_at IS NULL
       AND (expires_at IS NULL OR expires_at > now())
  `;
  const activeKeys = Number((keyRows[0] as Record<string, unknown> | undefined)?.active ?? 0);

  const packRows = await db()`
    SELECT id, created_at, summary
      FROM evidence_packs
     WHERE org_id = ${environment.org_id} AND environment_id = ${environment.id}
     ORDER BY created_at DESC LIMIT 1
  `;
  const previousPack = packRows[0] as Record<string, any> | undefined;

  const packCountRows = await db()`
    SELECT count(*)::int AS count FROM evidence_packs
     WHERE org_id = ${environment.org_id} AND environment_id = ${environment.id}
  `;
  const packCount = Number((packCountRows[0] as Record<string, unknown> | undefined)?.count ?? 0);

  const policyAuditRows = await db()`
    SELECT count(*)::int AS count
      FROM audit_log
     WHERE org_id = ${environment.org_id}
       AND action = 'policy.upserted'
       AND created_at >= ${filters.since}
       AND created_at <= ${filters.until}
  `;
  const policyAuditCount = Number(
    (policyAuditRows[0] as Record<string, unknown> | undefined)?.count ?? 0,
  );

  const recordRows = await db()`
    SELECT action_id, agent_id, principal_id, tool, decision, outcome_status,
           policy_id, policy_version, receipt_id, created_at, verified,
           payload->'outcome'->'outcome'->>'source' AS outcome_source
      FROM actions
     WHERE org_id = ${environment.org_id}
       AND environment_id = ${environment.id}
       AND created_at >= ${filters.since}
       AND created_at <= ${filters.until}
       AND (${agentId}::text IS NULL OR agent_id = ${agentId})
     ORDER BY created_at DESC LIMIT 500
  `;

  let policyItems: Array<Record<string, any>> = [];
  try {
    const response = await broker.listPolicies(environment);
    policyItems = Array.isArray(response.items)
      ? (response.items as Array<Record<string, any>>)
      : [];
  } catch {
    policyItems = [];
  }

  let keyEventItems: Array<Record<string, any>> = [];
  let keyEventsVerified: boolean | null = null;
  let integrity: Record<string, any> | null = null;
  try {
    const response = await broker.keyEvents(environment);
    keyEventItems = Array.isArray(response.items)
      ? (response.items as Array<Record<string, any>>)
      : [];
    keyEventsVerified =
      typeof response.verified === "boolean"
        ? response.verified
        : typeof response.signaturesValid === "boolean"
          ? response.signaturesValid
          : null;
  } catch {
    keyEventItems = [];
  }
  try {
    integrity = await broker.integrity(environment);
  } catch {
    integrity = null;
  }

  const transitionsInWindow = keyEventItems
    .filter((item) => isTransition(item) && within(asDate(item.at), filters.since, filters.until))
    .slice(0, 100);
  const policyEventsInWindow = keyEventItems.filter(
    (item) => item.kind === "policy.changed" && within(asDate(item.at), filters.since, filters.until),
  );
  const chainReceipts = Number(integrity?.chains?.receipts ?? 0);
  const anchors = Number(integrity?.anchors?.count ?? 0);
  const anchorLatest = integrity?.anchors?.latest?.at ?? integrity?.anchors?.latest?.txHash ?? null;
  const unanchoredAgents = Number(integrity?.chains?.unanchoredAgents ?? 0);
  const chainsVerified =
    typeof integrity?.chains?.verified === "boolean"
      ? integrity.chains.verified
      : integrity?.chains?.driftedAgents !== undefined
        ? Number(integrity.chains.driftedAgents) === 0
        : null;

  const total = Number(stats.total ?? 0);
  const completed = Number(stats.completed ?? 0);
  const provenance = Number(stats.with_provenance ?? 0);
  const brokerObserved = Number(stats.broker_observed ?? 0);
  const verified = Number(stats.verified ?? 0);
  const denied = Number(stats.denied ?? 0);
  const pendingReviews = Number(reviewStats.pending ?? 0);
  const resolvedReviews = Number(reviewStats.approved ?? 0) + Number(reviewStats.rejected ?? 0);
  const activeLinks = linkRows.filter((row) => new Date(row.expires_at as string) > new Date()).length;

  const reviewStatus: CoverageStatus =
    resolvedReviews > 0 ? (pendingReviews > 0 ? "partial" : "covered") : pendingReviews > 0 ? "partial" : "gap";
  const exportStatus: CoverageStatus =
    packCount > 0 || options.plannedPack ? "covered" : "gap";
  const anchorStatus: CoverageStatus = anchors > 0 ? "covered" : chainReceipts > 0 ? "partial" : "gap";

  const signals: EvidenceSignal[] = [
    signal("actions", "Action records", total, total, `${total} actions in the selected window`, {
      status: total > 0 ? "covered" : "gap",
      gap: "No actions were recorded in this window.",
    }),
    signal(
      "principal",
      "Principal attribution",
      Number(stats.with_principal ?? 0),
      total,
      `${Number(stats.with_principal ?? 0)} of ${total} actions carry a principal`,
      { gap: "Some actions have no principal attribution." },
    ),
    signal(
      "policy",
      "Policy decisions",
      Number(stats.with_policy ?? 0),
      total,
      `${Number(stats.with_policy ?? 0)} of ${total} actions reference a policy`,
      { gap: "Some actions are not bound to a policy version." },
    ),
    signal(
      "verified",
      "Independent verification",
      verified,
      total,
      `${verified} of ${total} records verify against the broker signature`,
      { gap: "Some records have not passed independent verification." },
    ),
    signal(
      "provenance",
      "Outcome provenance",
      provenance,
      completed,
      `${provenance} of ${completed} completed actions label the outcome source`,
      { gap: "Some outcomes do not say whether the agent or broker observed them." },
    ),
    signal(
      "reviews",
      "Human review",
      resolvedReviews,
      resolvedReviews + pendingReviews,
      `${resolvedReviews} resolved, ${pendingReviews} pending`,
      {
        status: reviewStatus,
        gap: pendingReviews
          ? `${pendingReviews} ${pendingReviews === 1 ? "review" : "reviews"} still ${pendingReviews === 1 ? "needs" : "need"} a decision.`
          : "No human review decisions in this window.",
      },
    ),
    signal(
      "denied",
      "Blocked actions",
      denied,
      total,
      `${denied} action(s) were blocked by policy`,
      { status: denied > 0 ? "covered" : "gap", gap: "No blocked actions in this window." },
    ),
    signal(
      "transitions",
      "Authority transitions",
      transitionsInWindow.length,
      transitionsInWindow.length,
      `${transitionsInWindow.length} signed transition(s) in the ledger`,
      {
        status: transitionsInWindow.length > 0 ? "covered" : "gap",
        gap: "No authority transitions in this window.",
      },
    ),
    signal(
      "policy_changes",
      "Policy change history",
      policyEventsInWindow.length,
      policyEventsInWindow.length,
      `${policyEventsInWindow.length} signed policy change(s)`,
      {
        status: policyEventsInWindow.length > 0 ? "covered" : "gap",
        gap: "No signed policy changes in this window.",
      },
    ),
    signal(
      "credentials",
      "Credential posture",
      activeKeys,
      activeKeys,
      `${activeKeys} active agent key(s)`,
      { status: activeKeys > 0 ? "covered" : "gap", gap: "No active agent credentials." },
    ),
    signal(
      "verification_links",
      "Shareable verification",
      activeLinks,
      activeLinks,
      `${activeLinks} active verification link(s)`,
      {
        status: activeLinks > 0 ? "covered" : "gap",
        gap: "No active public verification links.",
      },
    ),
    signal(
      "anchors",
      "Tamper-evident anchor",
      anchors,
      chainReceipts,
      anchors > 0 ? `${anchors} anchored batch(es)` : `${unanchoredAgents} agent chain(s) not anchored`,
      {
        status: anchorStatus,
        gap: "No on-chain anchor; chain integrity is verified locally only.",
      },
    ),
    signal(
      "export",
      "Review-ready export",
      packCount,
      packCount,
      options.plannedPack ? "This evidence pack" : `${packCount} evidence pack(s) built`,
      {
        status: exportStatus,
        gap: "No evidence pack has been built yet.",
      },
    ),
  ];

  const signalMap = new Map(signals.map((item) => [item.id, item]));
  const selectedFrameworks = FRAMEWORKS.filter((item) => filters.frameworks.includes(item.id));
  const frameworks: EvidenceFramework[] = selectedFrameworks.map((definition) => {
    const controls = definition.controls.map((control): EvidenceControl => {
      const evidence = control.evidence
        .map((id) => signalMap.get(id))
        .filter((item): item is EvidenceSignal => Boolean(item));
      const covered = evidence.filter((item) => item.status === "covered").length;
      const partial = evidence.filter((item) => item.status === "partial").length;
      const status: CoverageStatus =
        evidence.length > 0 && covered === evidence.length
          ? "covered"
          : covered > 0 || partial > 0
            ? "partial"
            : "gap";
      return {
        ...control,
        id: control.id,
        label: control.id,
        value: covered,
        total: evidence.length,
        status,
        detail: evidence.map((item) => `${item.label}: ${item.detail}`).join(" · "),
        gap: evidence.find((item) => item.status === "gap")?.gap,
        evidence: control.evidence,
      };
    });
    const covered = controls.filter((control) => control.status === "covered").length;
    const partial = controls.filter((control) => control.status === "partial").length;
    const gap = controls.filter((control) => control.status === "gap").length;
    return {
      id: definition.id,
      name: definition.name,
      description: definition.description,
      controls,
      covered,
      partial,
      gap,
      readiness: controls.length ? Math.round(((covered + partial * 0.5) / controls.length) * 100) : 0,
    };
  });

  const allControls = frameworks.flatMap((item) => item.controls);
  const coveredControls = allControls.filter((control) => control.status === "covered").length;
  const partialControls = allControls.filter((control) => control.status === "partial").length;
  const gapControls = allControls.filter((control) => control.status === "gap").length;
  const readinessScore = allControls.length
    ? Math.round(((coveredControls + partialControls * 0.5) / allControls.length) * 100)
    : 0;
  const readinessStatus = readinessScore >= 85 ? "ready" : readinessScore >= 55 ? "partial" : "gap";

  const gaps = signals
    .filter((item) => item.status !== "covered" && item.gap)
    .map((item) => item.gap as string);
  const uniqueGaps = [...new Set(gaps)].slice(0, 8);

  let delta: EvidencePackSummary["delta"] = null;
  if (previousPack) {
    const previousSummary = previousPack.summary as EvidencePackSummary | undefined;
    const sincePackAt =
      previousSummary?.version === 1 && previousSummary.window?.until
        ? previousSummary.window.until
        : asDate(previousPack.created_at);
    const deltaRows = await db()`
      SELECT count(*)::int AS actions,
             count(*) FILTER (WHERE decision = 'deny')::int AS denied
        FROM actions
       WHERE org_id = ${environment.org_id}
         AND environment_id = ${environment.id}
         AND created_at > ${sincePackAt}
         AND (${agentId}::text IS NULL OR agent_id = ${agentId})
    `;
    const deltaReviewRows = await db()`
      SELECT count(*)::int AS reviews
        FROM action_reviews
       WHERE org_id = ${environment.org_id}
         AND environment_id = ${environment.id}
         AND resolved_at > ${sincePackAt}
    `;
    const deltaPolicyRows = await db()`
      SELECT count(*)::int AS changes
        FROM audit_log
       WHERE org_id = ${environment.org_id}
         AND action = 'policy.upserted'
         AND created_at > ${sincePackAt}
    `;
    delta = {
      sincePackId: String(previousPack.id),
      sincePackAt,
      actions: Number((deltaRows[0] as Record<string, unknown> | undefined)?.actions ?? 0),
      denied: Number((deltaRows[0] as Record<string, unknown> | undefined)?.denied ?? 0),
      reviews: Number((deltaReviewRows[0] as Record<string, unknown> | undefined)?.reviews ?? 0),
      transitions: keyEventItems.filter(
        (item) => isTransition(item) && asDate(item.at) > sincePackAt,
      ).length,
      policyChanges: Number(
        (deltaPolicyRows[0] as Record<string, unknown> | undefined)?.changes ?? 0,
      ),
    };
  }

  return {
    version: 1,
    generatedAt: new Date().toISOString(),
    orgName,
    environmentName: environment.name,
    scope: { type: agentId ? "agent" : "environment", agentId },
    window: { since: filters.since, until: filters.until },
    recipients: filters.recipients,
    readiness: {
      score: readinessScore,
      status: readinessStatus,
      explanation:
        readinessStatus === "ready"
          ? "The selected controls have direct, verifiable evidence. This is evidence coverage, not a certification."
          : readinessStatus === "partial"
            ? "Most controls have evidence, but gaps remain. Close the items below before an external review."
            : "Important evidence is missing. Treat this pack as a gap list, not a completed audit.",
      covered: coveredControls,
      partial: partialControls,
      gap: gapControls,
      controls: allControls.length,
    },
    inventory: {
      actions: total,
      allowed: Number(stats.allowed ?? 0),
      denied,
      completed,
      failed: Number(stats.failed ?? 0),
      verified,
      agents: Number(stats.agents ?? 0),
      policies: policyItems.length || Number(stats.policy_count ?? 0),
      reviews: Number(reviewStats.total ?? 0),
      transitions: transitionsInWindow.length,
      verificationLinks: activeLinks,
      agentKeys: activeKeys,
      evidencePacks: packCount + (options.plannedPack ? 1 : 0),
      receipts: chainReceipts,
      anchors,
    },
    signals,
    frameworks,
    gaps: uniqueGaps,
    notes: [
      "Evidence coverage maps available records to framework controls; it is not a certification or legal opinion.",
      "A receipt proves the broker signed the record; it does not prove the underlying provider executed correctly.",
      "The downloaded archive can be verified offline with the open `tessera-verify` CLI.",
      ...(brokerObserved === 0 && completed > 0
        ? ["Direct bearer and AWS outcomes are agent-reported; proxy broker-held grants to add broker-observed evidence."]
        : []),
    ],
    delta,
    policies: policyItems.map((policy) => ({
      id: String(policy.id ?? ""),
      name: String(policy.name ?? policy.id ?? "policy"),
      version: Number(policy.version ?? 0),
      grants: Array.isArray(policy.grants) ? policy.grants : [],
    })),
    records: (recordRows as Array<Record<string, any>>).map((row) => ({
      actionId: String(row.action_id),
      agentId: String(row.agent_id),
      principalId: row.principal_id ? String(row.principal_id) : null,
      tool: String(row.tool),
      decision: String(row.decision),
      outcomeStatus: row.outcome_status ? String(row.outcome_status) : null,
      outcomeSource: row.outcome_source ? String(row.outcome_source) : null,
      policyId: row.policy_id ? String(row.policy_id) : null,
      policyVersion: row.policy_version === null ? null : Number(row.policy_version),
      receiptId: String(row.receipt_id),
      createdAt: asDate(row.created_at),
      verified: row.verified === null ? null : Boolean(row.verified),
    })),
    reviews: {
      total: Number(reviewStats.total ?? 0),
      pending: pendingReviews,
      approved: Number(reviewStats.approved ?? 0),
      rejected: Number(reviewStats.rejected ?? 0),
      items: (reviewItems as Array<Record<string, any>>).map((row) => ({
        id: String(row.id),
        actionId: String(row.action_id),
        status: String(row.status),
        reason: row.reason ? String(row.reason) : null,
        resolutionNote: row.resolution_note ? String(row.resolution_note) : null,
        createdAt: asDate(row.created_at),
        resolvedAt: row.resolved_at ? asDate(row.resolved_at) : null,
      })),
    },
    transitions: transitionsInWindow.map((item) => ({
      id: String(item.id ?? ""),
      kind: String(item.kind ?? item.details?.transitionType ?? "authority.transition"),
      target: String(item.details?.target ?? item.key_name ?? item.keyName ?? item.key_id ?? ""),
      at: asDate(item.at),
      eventHash: String(item.eventHash ?? item.event_hash ?? ""),
    })),
    verificationLinks: (linkRows as Array<Record<string, any>>).map((row) => ({
      id: String(row.id),
      actionId: String(row.action_id),
      createdAt: asDate(row.created_at),
      expiresAt: asDate(row.expires_at),
    })),
    proof: {
      chainsVerified,
      keyEventsVerified,
      chainReceipts,
      anchors,
      anchorLatest: anchorLatest ? String(anchorLatest) : null,
      unanchoredAgents,
    },
  };
}
