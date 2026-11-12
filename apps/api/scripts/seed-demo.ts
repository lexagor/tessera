import postgres from "postgres";

type Json = Record<string, unknown>;

const API_BASE = process.env.DEMO_API_URL ?? "http://127.0.0.1:8788";
const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  console.error("DATABASE_URL is required");
  process.exit(1);
}

const sql = postgres(databaseUrl, { max: 4, onnotice: () => {} });
let cookie = "";

async function request<T>(path: string, init: RequestInit = {}, agentKey?: string): Promise<T> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    ...(cookie ? { cookie } : {}),
    ...(agentKey ? { "x-api-key": agentKey } : {}),
    ...(init.headers as Record<string, string> | undefined),
  };
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers,
    redirect: init.redirect ?? "manual",
  });
  const text = await response.text();
  let body: unknown = text;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    /* keep text */
  }
  if (!response.ok) {
    throw new Error(`${init.method ?? "GET"} ${path} -> ${response.status}: ${text.slice(0, 300)}`);
  }
  return body as T;
}

function randomHash(seed: number): string {
  const hex = (seed % 0xffff).toString(16).padStart(4, "0");
  return `0x${(hex + "0123456789abcdef".repeat(4)).slice(0, 64)}`;
}

const tools: Array<{
  agent: string;
  tool: string;
  args: (index: number) => Json;
  risk: string;
  failureEvery?: number;
}> = [
  { agent: "support-copilot", tool: "stripe.refunds.create", args: (i) => ({ charge: `ch_support_${i}`, amount: [20, 80, 120, 450][i % 4], reason: "duplicate charge" }), risk: "medium" },
  { agent: "billing-agent", tool: "stripe.refunds.create", args: (i) => ({ charge: `ch_billing_${i}`, amount: [60, 240, 4200, 90][i % 4], reason: "customer request" }), risk: "critical", failureEvery: 9 },
  { agent: "billing-agent", tool: "stripe.charges.create", args: (i) => ({ customer: `cus_billing_${i}`, amount: [300, 700, 1400][i % 3] }), risk: "critical" },
  { agent: "release-bot", tool: "github.issues.create", args: (i) => ({ repo: "acme/platform", title: `Release checklist ${i}` }), risk: "medium" },
  { agent: "release-bot", tool: "github.pulls.create", args: (i) => ({ repo: "acme/platform", title: `Release ${i}` }), risk: "high", failureEvery: 7 },
  { agent: "data-analyst", tool: "aws:s3:GetObject", args: (i) => ({ bucket: "acme-reports", key: `q3/export-${i}.csv` }), risk: "low" },
  { agent: "security-agent", tool: "github.issues.create", args: (i) => ({ repo: "acme/security", title: `Triage finding ${i}` }), risk: "medium" },
  { agent: "sales-assistant", tool: "stripe.charges.create", args: (i) => ({ customer: `cus_sales_${i}`, amount: [120, 500, 900][i % 3] }), risk: "high" },
];

async function main(): Promise<void> {
  const login = await fetch(`${API_BASE}/auth/dev-login`, { redirect: "manual" });
  const setCookie = login.headers.get("set-cookie");
  if (!setCookie) throw new Error("dev login did not set a session cookie");
  cookie = setCookie.split(";")[0]!;

  const me = await request<{
    org: { id: string };
    environments: Array<{ id: string; name: string; broker_tenant: string }>;
  }>("/v1/me");
  const environment = me.environments[0];
  if (!environment) throw new Error("create an environment in the portal first");

  if (process.env.DEMO_RESET === "1") {
    await sql`DELETE FROM verification_links WHERE environment_id = ${environment.id}`;
    await sql`DELETE FROM evidence_packs WHERE environment_id = ${environment.id}`;
    await sql`DELETE FROM actions WHERE environment_id = ${environment.id}`;
    await sql`DELETE FROM usage_daily WHERE environment_id = ${environment.id}`;
    await sql`DELETE FROM agent_keys WHERE environment_id = ${environment.id}`;
    await sql`DELETE FROM integration_connections WHERE environment_id = ${environment.id}`;
    await sql`DELETE FROM audit_log WHERE org_id = ${me.org.id} AND details->>'environmentId' = ${environment.id}`;
  }

  await request("/v1/policies/demo-baseline", {
    method: "PUT",
    body: JSON.stringify({
      version: 1,
      name: "Demo baseline",
      fail_open: false,
      grants: [
        { resource: "stripe:refunds.create", constraints: [{ type: "max_number", field: "amount", value: 500 }] },
        { resource: "stripe:charges.create", constraints: [{ type: "max_number", field: "amount", value: 1000 }] },
        { resource: "github:issues.create" },
        { resource: "github:pulls.create" },
        { resource: "aws:s3:GetObject" },
        { resource: "aws:s3:PutObject" },
      ],
      limits: {},
    }),
  });

  const keyResponse = await request<{ key: string }>(`/v1/agent-keys?environmentId=${environment.id}`, {
    method: "POST",
    body: JSON.stringify({ name: "demo-seed-agent" }),
  });
  const agentKey = keyResponse.key;

  const created: Array<{ actionId: string; receiptId: string; allowed: boolean; failure: boolean }> = [];
  for (let index = 0; index < 56; index += 1) {
    const definition = tools[index % tools.length]!;
    const counter = Math.floor(index / tools.length);
    const args = definition.args(counter);
    const auth = await request<{
      decision: "allow" | "deny";
      receiptId: string;
      actionId: string;
    }>("/v1/authorize", {
      method: "POST",
      body: JSON.stringify({
        agentId: definition.agent,
        userId: ["maya.chen", "liam.patel", "sara.kim", "noah.williams"][index % 4],
        tool: definition.tool,
        intent: `demo action ${index + 1}`,
        args,
        riskClass: definition.risk,
        agentMeta: { agentVersion: "2026.11", environment: "production" },
      }),
    }, agentKey);
    const failure = definition.failureEvery ? index % definition.failureEvery === 0 : false;
    if (auth.decision === "allow") {
      await request("/v1/record", {
        method: "POST",
        body: JSON.stringify({
          agentId: definition.agent,
          receiptId: auth.receiptId,
          resultHash: randomHash(index + 17),
          status: failure ? "failure" : "success",
          errorClass: failure ? "ProviderError" : undefined,
        }),
      }, agentKey);
    }
    created.push({ actionId: auth.actionId, receiptId: auth.receiptId, allowed: auth.decision === "allow", failure });
  }

  const rows = await sql<{ action_id: string; outcome_status: string | null }[]>`
    SELECT action_id, outcome_status FROM actions
     WHERE environment_id = ${environment.id}
     ORDER BY created_at DESC, action_id
  `;
  const now = Date.now();
  for (const [index, row] of rows.entries()) {
    const dayOffset = (index * 5 + Math.floor(index / 7) * 3) % 14;
    const stamp = new Date(now - dayOffset * 86_400_000 - (index % 8) * 60_000).toISOString();
    const completed = row.outcome_status ? stamp : null;
    await sql`
      UPDATE actions SET created_at = ${stamp}, completed_at = ${completed}
       WHERE action_id = ${row.action_id}
    `;
  }

  await sql`DELETE FROM usage_daily WHERE environment_id = ${environment.id}`;
  const daily = await sql<{ day: string; actions: number; allowed: number; denied: number }[]>`
    SELECT to_char(created_at::date, 'YYYY-MM-DD') AS day,
           count(*)::int AS actions,
           sum(CASE WHEN decision = 'allow' THEN 1 ELSE 0 END)::int AS allowed,
           sum(CASE WHEN decision = 'deny' THEN 1 ELSE 0 END)::int AS denied
      FROM actions WHERE environment_id = ${environment.id}
     GROUP BY created_at::date ORDER BY created_at::date
  `;
  for (const row of daily) {
    await sql`
      INSERT INTO usage_daily (org_id, environment_id, day, actions, allowed, denied)
      VALUES (${me.org.id}, ${environment.id}, ${row.day}::date, ${row.actions}, ${row.allowed}, ${row.denied})
      ON CONFLICT (org_id, environment_id, day) DO UPDATE SET
        actions = EXCLUDED.actions, allowed = EXCLUDED.allowed, denied = EXCLUDED.denied
    `;
  }

  for (const row of rows) {
    await request(`/v1/actions/${row.action_id}`);
  }

  const firstAction = rows[0];
  if (firstAction) {
    await request("/v1/verification-links", {
      method: "POST",
      body: JSON.stringify({ actionId: firstAction.action_id }),
    });
  }

  const integrations = [
    { provider: "stripe", name: "Stripe billing", scopes: ["refunds", "charges"] },
    { provider: "github", name: "GitHub release automation", scopes: ["issues", "pulls"] },
    { provider: "aws", name: "AWS data lake", scopes: ["s3-read", "s3-write"] },
    { provider: "slack", name: "Slack support", scopes: ["chat", "history"] },
    { provider: "openai", name: "OpenAI support copilot", scopes: ["responses", "models"] },
    { provider: "zendesk", name: "Zendesk tickets", scopes: ["tickets-create", "tickets-read"] },
    { provider: "langchain", name: "LangChain tools", scopes: ["tool-invoke"] },
  ];
  for (const integration of integrations) {
    await request("/v1/integrations", {
      method: "POST",
      body: JSON.stringify(integration),
    });
  }
  const integrationActions = await sql<{ action_id: string }[]>`
    SELECT action_id FROM actions
     WHERE environment_id = ${environment.id} AND agent_id = 'tessera-integration-check'
  `;
  for (const row of integrationActions) {
    await request(`/v1/actions/${row.action_id}`);
  }
  await sql`
    UPDATE actions
       SET verified_at = completed_at + (interval '5 seconds' * (abs(hashtext(action_id)) % 12 + 1))
     WHERE environment_id = ${environment.id}
       AND verified = true
       AND completed_at IS NOT NULL
  `;

  const baselineUntil = new Date(now - 7 * 86_400_000).toISOString().slice(0, 10);
  const baselineSince = new Date(now - 30 * 86_400_000).toISOString().slice(0, 10);
  await request("/v1/evidence-packs", {
    method: "POST",
    body: JSON.stringify({
      since: baselineSince,
      until: baselineUntil,
      frameworks: ["soc2", "iso42001", "eu-ai-act", "nist-ai-rmf", "dora"],
    }),
  });

  await request("/v1/transitions", {
    method: "POST",
    body: JSON.stringify({
      type: "authority.stepped_up",
      target: "billing-agent",
      reason: "MFA challenge",
    }),
  });

  const reviewable = rows.find((row) => row.outcome_status === "success") ?? rows[0];
  if (reviewable) {
    const review = await request<{ id: string }>(`/v1/actions/${reviewable.action_id}/review`, {
      method: "POST",
      body: JSON.stringify({ reason: "High-value action requested a second reviewer" }),
    });
    await request(`/v1/reviews/${review.id}/decision`, {
      method: "POST",
      body: JSON.stringify({ decision: "approve", note: "Reviewed against the baseline policy" }),
    });
    const pending = rows.find((row) => row.action_id !== reviewable.action_id && row.outcome_status === "success");
    if (pending) {
      await request(`/v1/actions/${pending.action_id}/review`, {
        method: "POST",
        body: JSON.stringify({ reason: "Refund exceeds the standard reviewer threshold" }),
      });
    }
  }

  const finalPack = await request<{ id: string }>("/v1/evidence-packs", {
    method: "POST",
    body: JSON.stringify({
      since: baselineSince,
      until: new Date().toISOString().slice(0, 10),
      frameworks: ["soc2", "iso42001", "eu-ai-act", "nist-ai-rmf", "dora"],
      recipients: ["security@acme.example"],
    }),
  });
  const share = await request<{ url: string }>(`/v1/evidence-packs/${finalPack.id}/share`, {
    method: "POST",
    body: JSON.stringify({ expiresInDays: 30 }),
  });
  const totals = await sql<{ actions: number; agents: number }[]>`
    SELECT count(*)::int AS actions, count(DISTINCT agent_id)::int AS agents
      FROM actions WHERE environment_id = ${environment.id}
  `;

  console.log(JSON.stringify({ environment: environment.name, actions: totals[0]?.actions ?? rows.length, agents: totals[0]?.agents ?? new Set(tools.map((tool) => tool.agent)).size, integrations: integrations.length, evidencePack: finalPack.id, reviewerLink: share.url }, null, 2));
  await sql.end();
}

main().catch(async (error) => {
  console.error(error);
  await sql.end();
  process.exit(1);
});
