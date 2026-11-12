import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { api, environmentQuery, type AgentSummary } from "../api";
import { useWorkspace } from "../App";
import { Badge, Card, EmptyState, PageHeader, formatDate } from "@tessera/ui";

export function AgentsPage() {
  const { environmentId } = useWorkspace();
  const query = useQuery({
    queryKey: ["agents", environmentId],
    queryFn: () => api<{ items: AgentSummary[] }>(`/v1/agents${environmentQuery(environmentId)}`),
    enabled: Boolean(environmentId),
  });

  return (
    <>
      <PageHeader
        title="Agents"
        subtitle="Agents seen in this environment, their action volume, and denial rate."
      />
      <Card>
        {query.data?.items.length ? (
          <table className="tf-table">
            <thead>
              <tr>
                <th>Agent</th>
                <th>Actions</th>
                <th>Succeeded</th>
                <th>Denied</th>
                <th>Last seen</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {query.data.items.map((agent) => (
                <tr key={agent.agent_id}>
                  <td className="tf-mono">{agent.agent_id}</td>
                  <td>{agent.actions}</td>
                  <td>{agent.succeeded}</td>
                  <td>
                    {agent.denied > 0 ? (
                      <Badge tone="bad">{agent.denied}</Badge>
                    ) : (
                      <span className="tf-muted">0</span>
                    )}
                  </td>
                  <td className="tf-muted">{formatDate(agent.last_seen)}</td>
                  <td>
                    <Link
                      className="tf-btn ghost"
                      to={`/actions?agentId=${encodeURIComponent(agent.agent_id)}`}
                    >
                      View actions
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <EmptyState title="No agents yet">
            Once an agent calls the API with a valid agent key, it appears here.
          </EmptyState>
        )}
      </Card>
    </>
  );
}
