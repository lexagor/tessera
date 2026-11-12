import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { api, environmentQuery, type ActionSummary, type AgentSummary } from "../api";
import { useWorkspace } from "../App";
import { Badge, Button, Card, EmptyState, ErrorState, PageHeader, Skeleton, formatDate } from "@tessera/ui";
import { RiskBadge, Sparkline } from "../components/Charts";
import { relativeTime, riskForTool, riskRank, type RiskLevel } from "../lib/risk";

function recentDays(): string[] {
  return Array.from({ length: 14 }, (_, index) => {
    const date = new Date();
    date.setDate(date.getDate() - (13 - index));
    return date.toISOString().slice(0, 10);
  });
}

function agentSpark(actions: ActionSummary[]): number[] {
  const days = recentDays();
  return days.map(
    (day) => actions.filter((action) => String(action.createdAt).slice(0, 10) === day).length,
  );
}

export function AgentsPage() {
  const { environmentId } = useWorkspace();
  const agents = useQuery({
    queryKey: ["agents", environmentId],
    queryFn: () => api<{ items: AgentSummary[] }>(`/v1/agents${environmentQuery(environmentId)}`),
    enabled: Boolean(environmentId),
  });
  const actions = useQuery({
    queryKey: ["actions", environmentId, "agents"],
    queryFn: () =>
      api<{ items: ActionSummary[] }>(
        `/v1/actions?limit=100${environmentId ? `&environmentId=${environmentId}` : ""}`,
      ),
    enabled: Boolean(environmentId),
  });

  const grouped = useMemo(() => {
    const map = new Map<string, ActionSummary[]>();
    for (const action of actions.data?.items ?? []) {
      const current = map.get(action.agentId) ?? [];
      current.push(action);
      map.set(action.agentId, current);
    }
    return map;
  }, [actions.data]);

  return (
    <>
      <PageHeader
        title="Agents"
        subtitle="The actors in this environment, their blast radius, and their recent behavior."
        actions={<Link className="tf-btn" to="/keys">Agent keys</Link>}
      />
      {agents.isLoading || actions.isLoading ? (
        <div className="tf-agent-grid">
          {Array.from({ length: 4 }).map((_, index) => (
            <Card key={index}>
              <Skeleton width="42%" height={16} />
              <Skeleton width="70%" height={10} style={{ marginTop: 12 }} />
              <Skeleton width="100%" height={36} style={{ marginTop: 18 }} />
              <Skeleton width="60%" height={10} style={{ marginTop: 14 }} />
            </Card>
          ))}
        </div>
      ) : agents.isError || actions.isError ? (
        <Card>
          <ErrorState
            title="Agents are unavailable"
            message={agents.error instanceof Error ? agents.error.message : "Could not load the agent inventory."}
            action={<Button onClick={() => { void agents.refetch(); void actions.refetch(); }}>Retry</Button>}
          />
        </Card>
      ) : agents.data?.items.length ? (
        <div className="tf-agent-grid">
          {agents.data.items.map((agent) => {
            const agentActions = grouped.get(agent.agent_id) ?? [];
            const risk = agentActions.reduce<RiskLevel>((current, action) => {
              const next = riskForTool(action.tool, action.decision).level;
              return riskRank(next) > riskRank(current) ? next : current;
            }, "low");
            const tools = new Set(agentActions.map((action) => action.tool));
            const failed = agentActions.filter((action) => action.outcomeStatus === "failure").length;
            return (
              <Link className="tf-agent-card" to={`/agents/${encodeURIComponent(agent.agent_id)}`} key={agent.agent_id}>
                <Card>
                  <div className="tf-agent-card-head">
                    <span className="tf-agent-avatar tf-agent-avatar-lg">{agent.agent_id.slice(0, 1).toUpperCase()}</span>
                    <div className="tf-agent-card-name">
                      <strong>{agent.agent_id}</strong>
                      <span className="tf-muted">last seen {relativeTime(agent.last_seen)}</span>
                    </div>
                    <RiskBadge level={risk} />
                  </div>
                  <div className="tf-agent-card-stats">
                    <span><strong>{agent.actions}</strong> actions</span>
                    <span><strong>{tools.size}</strong> tools</span>
                    <span><strong>{failed}</strong> failed</span>
                    <span><strong>{agent.denied}</strong> denied</span>
                  </div>
                  <div className="tf-agent-card-spark">
                    <Sparkline values={agentSpark(agentActions)} width={240} height={36} />
                  </div>
                  <div className="tf-agent-card-foot">
                    <span className="tf-muted">{formatDate(agent.last_seen)}</span>
                    <span className="tf-agent-open">Open profile →</span>
                  </div>
                </Card>
              </Link>
            );
          })}
        </div>
      ) : (
        <Card>
          <EmptyState title="No agents yet">
            Once an agent calls the API with a valid agent key, it appears here.
          </EmptyState>
        </Card>
      )}
    </>
  );
}
