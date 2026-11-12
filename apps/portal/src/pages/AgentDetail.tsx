import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";

import { api, type ActionSummary, type AgentSummary } from "../api";
import { useWorkspace } from "../App";
import { Badge, Card, EmptyState, PageHeader, formatDate } from "@tessera/ui";
import { RiskBadge, Sparkline } from "../components/Charts";
import { relativeTime, riskForTool, riskRank, type RiskLevel } from "../lib/risk";

export function AgentDetailPage() {
  const { agentId = "" } = useParams();
  const { environmentId } = useWorkspace();
  const agents = useQuery({
    queryKey: ["agents", environmentId],
    queryFn: () => api<{ items: AgentSummary[] }>(`/v1/agents?environmentId=${encodeURIComponent(environmentId)}`),
    enabled: Boolean(environmentId),
  });
  const actions = useQuery({
    queryKey: ["actions", environmentId, "agent", agentId],
    queryFn: () =>
      api<{ items: ActionSummary[] }>(
        `/v1/actions?limit=100&agentId=${encodeURIComponent(agentId)}&environmentId=${encodeURIComponent(environmentId)}`,
      ),
    enabled: Boolean(environmentId && agentId),
  });

  const agent = agents.data?.items.find((item) => item.agent_id === agentId);
  const items = actions.data?.items ?? [];
  const risk = useMemo(
    () =>
      items.reduce<RiskLevel>((current, action) => {
        const next = riskForTool(action.tool, action.decision).level;
        return riskRank(next) > riskRank(current) ? next : current;
      }, "low"),
    [items],
  );
  const tools = useMemo(() => {
    const map = new Map<string, { count: number; last: string; risk: RiskLevel }>();
    for (const action of items) {
      const existing = map.get(action.tool);
      const next = riskForTool(action.tool, action.decision).level;
      const last =
        !existing || new Date(action.createdAt).getTime() > new Date(existing.last).getTime()
          ? action.createdAt
          : existing.last;
      map.set(action.tool, {
        count: (existing?.count ?? 0) + 1,
        last,
        risk: existing && riskRank(existing.risk) > riskRank(next) ? existing.risk : next,
      });
    }
    return [...map.entries()].sort((a, b) => b[1].count - a[1].count);
  }, [items]);
  const principals = useMemo(() => [...new Set(items.map((action) => action.principalId))], [items]);
  const recent = items.slice(0, 12);
  const failed = items.filter((action) => action.outcomeStatus === "failure").length;
  const spark = Array.from({ length: 14 }, (_, index) => {
    const day = new Date();
    day.setDate(day.getDate() - (13 - index));
    const key = day.toISOString().slice(0, 10);
    return items.filter((action) => String(action.createdAt).slice(0, 10) === key).length;
  });

  if (actions.isLoading) return <Card>Loading agent…</Card>;
  if (!agent && items.length === 0) {
    return <Card><EmptyState title="Agent not found">This agent has no recorded actions in the environment.</EmptyState></Card>;
  }

  return (
    <>
      <PageHeader
        title={agentId}
        subtitle={agent ? `${agent.actions} actions · last seen ${relativeTime(agent.last_seen)}` : "Agent activity"}
        actions={
          <>
            <Link className="tf-btn" to={`/actions?agentId=${encodeURIComponent(agentId)}`}>All actions</Link>
            <Link className="tf-btn ghost" to="/agents">Back to agents</Link>
          </>
        }
      />

      <div className="tf-stat-row">
        <Card>
          <div className="tf-kpi-label">Risk</div>
          <div className="tf-agent-detail-risk"><RiskBadge level={risk} /></div>
          <div className="tf-muted" style={{ marginTop: 6 }}>highest observed</div>
        </Card>
        <Card>
          <div className="tf-kpi-label">Actions</div>
          <div className="tf-stat-value">{items.length}</div>
          <div className="tf-muted">{failed} failed outcomes</div>
        </Card>
        <Card>
          <div className="tf-kpi-label">Tools</div>
          <div className="tf-stat-value">{tools.length}</div>
          <div className="tf-muted">reachable surfaces</div>
        </Card>
        <Card>
          <div className="tf-kpi-label">Principals</div>
          <div className="tf-stat-value">{principals.length}</div>
          <div className="tf-muted">delegating humans</div>
        </Card>
      </div>

      <Card style={{ marginTop: 18 }}>
        <div className="tf-actions" style={{ justifyContent: "space-between" }}>
          <div>
            <h2 style={{ margin: 0, fontSize: 18 }}>Behavior</h2>
            <p className="tf-muted" style={{ margin: "3px 0 0" }}>Recent action volume across the environment.</p>
          </div>
          <span className="tf-agent-detail-spark"><Sparkline values={spark} width={220} height={42} /></span>
        </div>
      </Card>

      <div className="tf-grid" style={{ marginTop: 18, gridTemplateColumns: "1fr 1fr" }}>
        <Card>
          <h2 style={{ margin: 0, fontSize: 18 }}>Tools</h2>
          <div className="tf-list" style={{ marginTop: 10 }}>
            {tools.map(([tool, summary]) => (
              <div className="tf-list-row" key={tool}>
                <div>
                  <div className="tf-mono">{tool}</div>
                  <div className="tf-muted">{summary.count} actions · last {relativeTime(summary.last)}</div>
                </div>
                <RiskBadge level={summary.risk} />
              </div>
            ))}
          </div>
        </Card>
        <Card>
          <h2 style={{ margin: 0, fontSize: 18 }}>Principals</h2>
          <div className="tf-list" style={{ marginTop: 10 }}>
            {principals.map((principal) => (
              <div className="tf-list-row" key={principal}>
                <div>
                  <div className="tf-mono">{principal}</div>
                  <div className="tf-muted">delegating principal</div>
                </div>
                <Badge tone="muted">identity</Badge>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <Card style={{ marginTop: 18 }}>
        <div className="tf-actions" style={{ justifyContent: "space-between" }}>
          <h2 style={{ margin: 0, fontSize: 18 }}>Recent actions</h2>
          <Link className="tf-btn ghost" to={`/actions?agentId=${encodeURIComponent(agentId)}`}>View all</Link>
        </div>
        {recent.length ? (
          <table className="tf-table">
            <thead>
              <tr><th>Tool</th><th>Risk</th><th>Decision</th><th>Outcome</th><th>When</th></tr>
            </thead>
            <tbody>
              {recent.map((action) => {
                const actionRisk = riskForTool(action.tool, action.decision);
                return (
                  <tr key={action.actionId}>
                    <td><Link to={`/actions/${action.actionId}`}>{action.tool}</Link></td>
                    <td><RiskBadge level={actionRisk.level} /></td>
                    <td><Badge tone={action.decision === "allow" ? "ok" : "bad"}>{action.decision}</Badge></td>
                    <td><Badge tone={action.outcomeStatus === "success" ? "ok" : action.outcomeStatus ? "warn" : "muted"}>{action.outcomeStatus ?? "pending"}</Badge></td>
                    <td className="tf-muted">{formatDate(action.createdAt)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        ) : <EmptyState title="No actions yet">The agent will appear here once it acts.</EmptyState>}
      </Card>
    </>
  );
}
