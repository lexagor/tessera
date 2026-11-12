import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import {
  api,
  environmentQuery,
  type ActionSummary,
  type AgentKey,
  type Usage,
} from "../api";
import { useWorkspace } from "../App";
import {
  Badge,
  Button,
  Card,
  CopyRow,
  EmptyState,
  PageHeader,
  formatDate,
} from "@tessera/ui";

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
    queryKey: ["actions", environmentId, "recent"],
    queryFn: () =>
      api<{ items: ActionSummary[] }>(
        `/v1/actions?limit=5${environmentId ? `&environmentId=${environmentId}` : ""}`,
      ),
    enabled: Boolean(environmentId),
  });
  const keys = useQuery({
    queryKey: ["agent-keys", environmentId],
    queryFn: () =>
      api<{ items: AgentKey[] }>(
        `/v1/agent-keys${environmentQuery(environmentId)}`,
      ),
    enabled: Boolean(environmentId),
  });
  const agents = useQuery({
    queryKey: ["agents", environmentId],
    queryFn: () =>
      api<{ items: Array<{ agent_id: string; actions: number; last_seen: string }> }>(
        `/v1/agents${environmentQuery(environmentId)}`,
      ),
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

  const totalActions = actions.data?.items.length ?? 0;
  const denied = actions.data?.items.filter((action) => action.decision === "deny").length ?? 0;
  const deniedRate = totalActions === 0 ? 0 : Math.round((denied / totalActions) * 100);
  const activeKey = keys.data?.items.find((key) => !key.revoked_at);
  const firstAgent = agents.data?.items[0]?.agent_id;

  return (
    <>
      <PageHeader
        title={`Welcome, ${me.user.name || me.user.email.split("@")[0]}`}
        subtitle="Instrument one action, prove it to a reviewer, then expand."
        actions={
          <>
            {firstAgent ? (
              <Link className="tf-btn" to={`/actions?agentId=${encodeURIComponent(firstAgent)}`}>
                View actions
              </Link>
            ) : null}
            {environmentId ? (
              <Link className="tf-btn primary" to="/keys">
                Create agent key
              </Link>
            ) : null}
          </>
        }
      />

      {error ? <div className="tf-error">{error}</div> : null}

      {!environmentId ? (
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
      ) : (
        <div className="tf-grid tf-grid-3">
          <Card>
            <div className="tf-kpi-label">Actions</div>
            <div className="tf-kpi">{usage.data?.used ?? 0}</div>
            <div className="tf-muted">This month</div>
          </Card>
          <Card>
            <div className="tf-kpi-label">Denied</div>
            <div className="tf-kpi">{deniedRate}%</div>
            <div className="tf-muted">Last {totalActions} actions</div>
          </Card>
          <Card>
            <div className="tf-kpi-label">Agents</div>
            <div className="tf-kpi">{agents.data?.items.length ?? 0}</div>
            <div className="tf-muted">Seen in this environment</div>
          </Card>
          <Card>
            <div className="tf-kpi-label">Plan</div>
            <div className="tf-kpi">{usage.data?.plan ?? me.org.plan}</div>
            <div className="tf-muted">
              {usage.data ? `${usage.data.remaining.toLocaleString()} actions remaining` : "—"}
            </div>
          </Card>
        </div>
      )}

      {environmentId ? (
        <div className="tf-grid" style={{ marginTop: 18, gridTemplateColumns: "1.2fr .8fr" }}>
          <Card>
            <div className="tf-actions" style={{ justifyContent: "space-between", marginBottom: 8 }}>
              <h2 style={{ margin: 0, fontSize: 18 }}>Recent actions</h2>
              <Link className="tf-btn ghost" to="/actions">View all</Link>
            </div>
            {actions.data?.items.length ? (
              <table className="tf-table">
                <thead>
                  <tr>
                    <th>Tool</th>
                    <th>Agent</th>
                    <th>Decision</th>
                    <th>Outcome</th>
                    <th>When</th>
                  </tr>
                </thead>
                <tbody>
                  {actions.data.items.map((action) => (
                    <tr key={action.actionId}>
                      <td><Link to={`/actions/${action.actionId}`}>{action.tool}</Link></td>
                      <td className="tf-mono">{action.agentId}</td>
                      <td>
                        <Badge tone={action.decision === "allow" ? "ok" : "bad"}>
                          {action.decision}
                        </Badge>
                      </td>
                      <td>{action.outcomeStatus || "—"}</td>
                      <td className="tf-muted">{formatDate(action.createdAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <EmptyState title="No actions yet">
                Create an agent key, run the quickstart, and the first signed action will appear here.
              </EmptyState>
            )}
          </Card>

          <Card>
            <h2 style={{ margin: 0, fontSize: 18 }}>Onboarding</h2>
            <div className="tf-list">
              <div className="tf-list-row">
                <div>
                  <strong>1. Environment</strong>
                  <div className="tf-muted">{me.environments.find((e) => e.id === environmentId)?.name}</div>
                </div>
                <Badge tone="ok">ready</Badge>
              </div>
              <div className="tf-list-row">
                <div>
                  <strong>2. Agent key</strong>
                  <div className="tf-muted">{activeKey ? `${activeKey.prefix}…` : "none yet"}</div>
                </div>
                {activeKey ? <Badge tone="ok">ready</Badge> : <Badge tone="warn">next</Badge>}
              </div>
              <div className="tf-list-row">
                <div>
                  <strong>3. First action</strong>
                  <div className="tf-muted">{totalActions > 0 ? "recorded" : "waiting"}</div>
                </div>
                {totalActions > 0 ? <Badge tone="ok">ready</Badge> : <Badge tone="muted">pending</Badge>}
              </div>
            </div>

            {!activeKey ? (
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
            ) : null}

            {createdKey ? (
              <div style={{ marginTop: 16 }}>
                <p className="tf-muted" style={{ marginBottom: 6 }}>
                  Store this key now. The portal will not show it again.
                </p>
                <CopyRow value={createdKey} />
                <p className="tf-muted" style={{ marginTop: 12 }}>Run this against your agent:</p>
                <pre className="tf-code">{`const tessera = createClient({
  endpoint: "${window.location.origin}",
  apiKey: "${createdKey}",
  agentId: "billing-agent",
  userId: "user_42",
});`}</pre>
              </div>
            ) : null}
          </Card>
        </div>
      ) : null}
    </>
  );
}
