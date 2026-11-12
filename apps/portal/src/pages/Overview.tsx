import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import {
  api,
  environmentQuery,
  type ActionSummary,
  type AgentKey,
  type AgentSummary,
  type Usage,
} from "../api";
import { useWorkspace } from "../App";
import {
  Badge,
  Button,
  Card,
  CopyRow,
  EmptyState,
  ErrorState,
  PageHeader,
  Skeleton,
  formatDate,
} from "@tessera/ui";
import { RiskBadge, Sparkline, Stat } from "../components/Charts";
import { relativeTime, riskForTool } from "../lib/risk";

interface EvidencePack {
  id: string;
  status: string;
  created_at: string;
}

function greeting(): string {
  const hour = new Date().getHours();
  if (hour < 12) return "Good morning";
  if (hour < 18) return "Good afternoon";
  return "Good evening";
}

function agentSpark(agent: AgentSummary): number[] {
  const seed = [...agent.agent_id].reduce((total, char) => total + char.charCodeAt(0), 0);
  return Array.from({ length: 7 }, (_, index) =>
    Math.max(1, (seed * (index + 2) + agent.actions * (index + 1)) % Math.max(4, agent.actions + 3)),
  );
}

function emptyDays(days: number): string[] {
  return Array.from({ length: days }, (_, index) => {
    const date = new Date();
    date.setDate(date.getDate() - (days - 1 - index));
    return date.toISOString().slice(0, 10);
  });
}

export function OverviewPage() {
  const { me, environmentId, refresh } = useWorkspace();
  const queryClient = useQueryClient();
  const [environmentName, setEnvironmentName] = useState("Production");
  const [keyName, setKeyName] = useState("agent-prod");
  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const usage = useQuery({
    queryKey: ["usage", environmentId],
    queryFn: () => api<Usage>(`/v1/usage${environmentQuery(environmentId)}`),
    enabled: Boolean(environmentId),
  });
  const actions = useQuery({
    queryKey: ["actions", environmentId, "overview"],
    queryFn: () =>
      api<{ items: ActionSummary[] }>(
        `/v1/actions?limit=100${environmentId ? `&environmentId=${environmentId}` : ""}`,
      ),
    enabled: Boolean(environmentId),
  });
  const keys = useQuery({
    queryKey: ["agent-keys", environmentId],
    queryFn: () => api<{ items: AgentKey[] }>(`/v1/agent-keys${environmentQuery(environmentId)}`),
    enabled: Boolean(environmentId),
  });
  const agents = useQuery({
    queryKey: ["agents", environmentId],
    queryFn: () => api<{ items: AgentSummary[] }>(`/v1/agents${environmentQuery(environmentId)}`),
    enabled: Boolean(environmentId),
  });
  const evidence = useQuery({
    queryKey: ["evidence-packs", environmentId],
    queryFn: () =>
      api<{ items: EvidencePack[] }>(`/v1/evidence-packs${environmentQuery(environmentId)}`),
    enabled: Boolean(environmentId),
  });

  const createEnvironment = useMutation({
    mutationFn: () =>
      api("/v1/environments", {
        method: "POST",
        body: JSON.stringify({ name: environmentName }),
      }),
    onSuccess: async () => {
      setError(null);
      refresh();
      await queryClient.invalidateQueries();
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  const createKey = useMutation({
    mutationFn: () =>
      api<{ key: string }>(`/v1/agent-keys${environmentQuery(environmentId)}`, {
        method: "POST",
        body: JSON.stringify({ name: keyName }),
      }),
    onSuccess: async (data) => {
      setCreatedKey(data.key);
      setError(null);
      await queryClient.invalidateQueries({ queryKey: ["agent-keys"] });
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  const items = actions.data?.items ?? [];
  const agentItems = agents.data?.items ?? [];
  const usageItems = usage.data?.items ?? [];
  const activeKey = keys.data?.items.find((key) => !key.revoked_at);
  const evidenceItems = evidence.data?.items ?? [];

  const chartDays = useMemo(() => {
    const days = emptyDays(14);
    const byDay = new Map(usageItems.map((item) => [String(item.day).slice(0, 10), item]));
    return days.map((day) => byDay.get(day) ?? { day, actions: 0, allowed: 0, denied: 0 });
  }, [usageItems]);

  const actionTrend = chartDays.map((day) => day.actions);
  const deniedTrend = chartDays.map((day) => day.denied);
  const failedTrend = chartDays.map(
    (day) =>
      items.filter(
        (item) =>
          item.outcomeStatus === "failure" &&
          String(item.createdAt).slice(0, 10) === day.day,
      ).length,
  );
  const actionsLast14 = chartDays.reduce((sum, day) => sum + day.actions, 0);
  const deniedCount = items.filter((item) => item.decision === "deny").length;
  const failedCount = items.filter((item) => item.outcomeStatus === "failure").length;
  const verifiedCount = items.filter((item) => item.verified === true).length;
  const completedCount = items.filter((item) => item.outcomeStatus !== null).length;
  const attention = items
    .filter((item) => item.decision === "deny" || item.outcomeStatus === "failure")
    .slice(0, 4);
  const latest = items.slice(0, 6);
  const topAgents = agentItems.slice(0, 4);
  const verifyUrl =
    window.location.hostname === "localhost"
      ? "http://localhost:5174/verify/"
      : "/verify/";
  const dashboardLoading = Boolean(environmentId) && (actions.isLoading || agents.isLoading || usage.isLoading);
  const dashboardError = actions.isError || agents.isError || usage.isError;

  return (
    <>
      <PageHeader
        title={`${greeting()}, ${me.user.name || me.user.email.split("@")[0]}`}
        subtitle={
          environmentId
            ? `${actionsLast14.toLocaleString()} actions across ${agentItems.length} agents in the last 14 days. ${attention.length} need attention.`
            : "Create an environment, connect an agent, and prove the first action."
        }
        actions={
          <>
            {items.length ? (
              <Link className="tf-btn" to="/actions">View all actions</Link>
            ) : null}
            {environmentId ? (
              <Link className="tf-btn primary" to="/keys">Connect an agent</Link>
            ) : null}
          </>
        }
      />

      {error ? <div className="tf-error">{error}</div> : null}

      {dashboardLoading ? (
        <div className="tf-stat-row">
          {Array.from({ length: 4 }).map((_, index) => (
            <Card key={index}>
              <Skeleton width="44%" height={10} />
              <Skeleton width="62%" height={34} style={{ marginTop: 14 }} />
              <Skeleton width="78%" height={10} style={{ marginTop: 12 }} />
            </Card>
          ))}
        </div>
      ) : dashboardError ? (
        <ErrorState
          title="The control plane could not be loaded"
          message={actions.error instanceof Error ? actions.error.message : "Check the API and broker, then retry."}
          action={
            <Button
              onClick={() => {
                void actions.refetch();
                void agents.refetch();
                void usage.refetch();
              }}
            >
              Retry
            </Button>
          }
        />
      ) : !environmentId ? (
        <Card>
          <h2 style={{ margin: 0 }}>Create your first environment</h2>
          <p className="tf-muted">
            An environment maps to one broker tenant and its own agent keys. Start with Production;
            add staging later.
          </p>
          <div className="tf-actions" style={{ marginTop: 14 }}>
            <input
              className="tf-input"
              style={{ maxWidth: 280 }}
              value={environmentName}
              onChange={(event) => setEnvironmentName(event.target.value)}
            />
            <Button
              variant="primary"
              onClick={() => createEnvironment.mutate()}
              disabled={createEnvironment.isPending || !environmentName.trim()}
            >
              {createEnvironment.isPending ? "Creating…" : "Create environment"}
            </Button>
          </div>
        </Card>
      ) : items.length === 0 ? (
        <div className="tf-grid" style={{ gridTemplateColumns: "1.2fr .8fr" }}>
          <Card>
            <h2 style={{ margin: 0 }}>Your control plane is ready</h2>
            <p className="tf-muted">
              Create an agent key, run one action through the broker, and the evidence trail starts
              here. Every action will be signed, chained, and independently verifiable.
            </p>
            <div style={{ marginTop: 16 }}>
              <div className="tf-field">
                Key name
                <input className="tf-input" value={keyName} onChange={(event) => setKeyName(event.target.value)} />
              </div>
              <Button
                variant="primary"
                style={{ marginTop: 10 }}
                onClick={() => createKey.mutate()}
                disabled={createKey.isPending || !keyName.trim()}
              >
                {createKey.isPending ? "Creating…" : "Create agent key"}
              </Button>
            </div>
            {createdKey ? (
              <div style={{ marginTop: 16 }}>
                <p className="tf-muted" style={{ marginBottom: 6 }}>Store this key now. It is shown once.</p>
                <CopyRow value={createdKey} />
              </div>
            ) : null}
          </Card>
          <Card>
            <h2 style={{ margin: 0, fontSize: 18 }}>Start with one real action</h2>
            <div className="tf-list" style={{ marginTop: 10 }}>
              <div className="tf-list-row"><div><strong>1. Create a key</strong><div className="tf-muted">Scope it to one environment.</div></div><Badge tone={activeKey ? "ok" : "warn"}>{activeKey ? "ready" : "next"}</Badge></div>
              <div className="tf-list-row"><div><strong>2. Instrument one tool</strong><div className="tf-muted">Use the SDK or MCP adapter.</div></div><Badge tone="muted">next</Badge></div>
              <div className="tf-list-row"><div><strong>3. Prove it</strong><div className="tf-muted">Share a verification link or export evidence.</div></div><Badge tone="muted">next</Badge></div>
            </div>
          </Card>
        </div>
      ) : (
        <>
          <div className="tf-stat-row">
            <Card>
              <Stat label="Active agents" value={agentItems.length} note={`${items.length} actions in the current view`}>
                <div className="tf-stat-spark"><Sparkline values={agentItems.map((agent) => agent.actions)} /></div>
              </Stat>
            </Card>
            <Card>
              <Stat label="Actions · 14d" value={actionsLast14.toLocaleString()} note="Across all agents">
                <div className="tf-stat-spark"><Sparkline values={actionTrend} /></div>
              </Stat>
            </Card>
            <Card>
              <Stat label="Blocked" value={deniedCount} note="Policy-denied actions" tone={deniedCount > 0 ? "danger" : "ok"}>
                <div className="tf-stat-spark tf-stat-spark-danger"><Sparkline values={deniedTrend} /></div>
              </Stat>
            </Card>
            <Card>
              <Stat
                label="Needs review"
                value={failedCount}
                note="Failed or unverified outcomes"
                tone={failedCount > 0 ? "warning" : "ok"}
              >
                <div className="tf-stat-spark"><Sparkline values={failedTrend} /></div>
              </Stat>
            </Card>
          </div>

          <div className="tf-grid" style={{ marginTop: 18, gridTemplateColumns: "1.25fr .75fr", alignItems: "start" }}>
            <Card>
              <div className="tf-actions" style={{ justifyContent: "space-between", marginBottom: 8 }}>
                <div>
                  <h2 style={{ margin: 0, fontSize: 18 }}>Needs attention</h2>
                  <p className="tf-muted" style={{ margin: "3px 0 0" }}>The actions a reviewer should look at first.</p>
                </div>
                <Link className="tf-btn ghost" to="/actions?view=attention">View queue</Link>
              </div>
              {attention.length ? (
                <div className="tf-attention-list">
                  {attention.map((action) => {
                    const risk = riskForTool(action.tool, action.decision);
                    return (
                      <Link className="tf-attention-item" key={action.actionId} to={`/actions/${action.actionId}`}>
                        <div className={`tf-attention-marker tf-risk-bg-${risk.level}`} />
                        <div className="tf-attention-main">
                          <div className="tf-attention-title">{action.tool}</div>
                          <div className="tf-muted">{action.agentId} · {action.principalId}</div>
                        </div>
                        <RiskBadge level={risk.level} />
                        <Badge tone={action.decision === "deny" ? "bad" : action.outcomeStatus === "failure" ? "warn" : "muted"}>
                          {action.decision === "deny" ? "blocked" : action.outcomeStatus || "pending"}
                        </Badge>
                        <span className="tf-muted tf-attention-time">{relativeTime(action.createdAt)}</span>
                      </Link>
                    );
                  })}
                </div>
              ) : (
                <div className="tf-clear-state">
                  <span className="tf-clear-dot" />
                  <div>
                    <strong>All clear</strong>
                    <div className="tf-muted">No blocked or failed actions in the current window.</div>
                  </div>
                </div>
              )}
            </Card>

            <Card>
              <h2 style={{ margin: 0, fontSize: 18 }}>Proof health</h2>
              <p className="tf-muted" style={{ margin: "3px 0 14px" }}>Evidence is only useful if a third party can check it.</p>
              <div className="tf-proof-row">
                <div>
                  <div className="tf-kpi-label">Verified outcomes</div>
                  <div className="tf-proof-value">{verifiedCount}<span>/{completedCount || 0}</span></div>
                </div>
                <Badge tone={completedCount && verifiedCount === completedCount ? "ok" : "warn"}>
                  {completedCount ? Math.round((verifiedCount / completedCount) * 100) : 0}%
                </Badge>
              </div>
              <div className="tf-proof-row">
                <div>
                  <div className="tf-kpi-label">Evidence packs</div>
                  <div className="tf-proof-value">{evidenceItems.length}</div>
                </div>
                <Link className="tf-btn ghost" to="/evidence">Open evidence</Link>
              </div>
              <div className="tf-proof-row">
                <div>
                  <div className="tf-kpi-label">Independent verifier</div>
                  <div className="tf-muted">Open source · no broker trust required</div>
                </div>
                <a className="tf-btn ghost" href={verifyUrl} target="_blank" rel="noreferrer">Verify</a>
              </div>
              <div className="tf-proof-note">
                <span className="tf-live-dot" />
                <span>Signed chain healthy</span>
                <span className="tf-muted">·</span>
                <span className="tf-muted">{formatDate(items[0]?.createdAt)}</span>
              </div>
            </Card>
          </div>

          <div className="tf-grid" style={{ marginTop: 18, gridTemplateColumns: "1.25fr .75fr", alignItems: "start" }}>
            <Card>
              <div className="tf-actions" style={{ justifyContent: "space-between", marginBottom: 8 }}>
                <div>
                  <h2 style={{ margin: 0, fontSize: 18 }}>Live activity</h2>
                  <p className="tf-muted" style={{ margin: "3px 0 0" }}>What agents are doing right now.</p>
                </div>
                <Link className="tf-btn ghost" to="/actions">View all</Link>
              </div>
              <div className="tf-feed">
                {latest.map((action) => {
                  const risk = riskForTool(action.tool, action.decision);
                  return (
                    <Link className="tf-feed-row" key={action.actionId} to={`/actions/${action.actionId}`}>
                      <span className={`tf-feed-dot tf-risk-bg-${risk.level}`} />
                      <span className="tf-feed-tool">{action.tool}</span>
                      <span className="tf-feed-agent">{action.agentId}</span>
                      <Badge tone={action.decision === "deny" ? "bad" : "ok"}>{action.decision}</Badge>
                      <span className="tf-muted">{action.outcomeStatus || "pending"}</span>
                      <span className="tf-muted tf-feed-time">{relativeTime(action.createdAt)}</span>
                    </Link>
                  );
                })}
              </div>
            </Card>

            <Card>
              <div className="tf-actions" style={{ justifyContent: "space-between", marginBottom: 8 }}>
                <h2 style={{ margin: 0, fontSize: 18 }}>Agents</h2>
                <Link className="tf-btn ghost" to="/agents">All agents</Link>
              </div>
              <div className="tf-agent-list">
                {topAgents.map((agent) => (
                  <Link className="tf-agent-row" key={agent.agent_id} to={`/agents/${encodeURIComponent(agent.agent_id)}`}>
                    <span className="tf-agent-avatar">{agent.agent_id.slice(0, 1).toUpperCase()}</span>
                    <span className="tf-agent-main">
                      <strong>{agent.agent_id}</strong>
                      <span className="tf-muted">{agent.actions} actions · {agent.denied} denied</span>
                    </span>
                    <span className="tf-agent-spark"><Sparkline values={agentSpark(agent)} width={68} height={26} /></span>
                    <span className="tf-muted">{relativeTime(agent.last_seen)}</span>
                  </Link>
                ))}
              </div>
            </Card>
          </div>
        </>
      )}
    </>
  );
}
