import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";

import { api, type ActionSummary } from "../api";
import { useWorkspace } from "../App";
import { Badge, Button, Card, EmptyState, PageHeader, formatDate, shortHash } from "@tessera/ui";
import { RiskBadge } from "../components/Charts";
import { riskForTool, riskRank } from "../lib/risk";

type View = "all" | "attention" | "blocked" | "high";

const VIEWS: Array<{ id: View; label: string }> = [
  { id: "all", label: "All actions" },
  { id: "attention", label: "Needs attention" },
  { id: "blocked", label: "Blocked" },
  { id: "high", label: "High risk" },
];

export function ActionsPage() {
  const { environmentId } = useWorkspace();
  const [searchParams, setSearchParams] = useSearchParams();
  const agentId = searchParams.get("agentId") ?? "";
  const tool = searchParams.get("tool") ?? "";
  const decision = searchParams.get("decision") ?? "";
  const outcome = searchParams.get("outcome") ?? "";
  const view = (searchParams.get("view") as View | null) ?? "all";
  const [cursor, setCursor] = useState<string | null>(null);
  const [pages, setPages] = useState<ActionSummary[]>([]);

  const query = useQuery({
    queryKey: ["actions", environmentId, agentId, tool, decision, outcome, view, cursor],
    queryFn: async () => {
      const params = new URLSearchParams();
      params.set("limit", view === "all" ? "25" : "100");
      if (environmentId) params.set("environmentId", environmentId);
      if (agentId) params.set("agentId", agentId);
      if (tool) params.set("tool", tool);
      if (decision) params.set("decision", decision);
      if (outcome) params.set("outcome", outcome);
      if (cursor) params.set("cursor", cursor);
      const result = await api<{ items: ActionSummary[]; nextCursor: string | null }>(
        `/v1/actions?${params.toString()}`,
      );
      setPages((current) => (cursor ? [...current, ...result.items] : result.items));
      return result;
    },
  });

  function updateFilter(key: string, value: string) {
    const next = new URLSearchParams(searchParams);
    if (value) next.set(key, value);
    else next.delete(key);
    if (key !== "cursor") {
      setCursor(null);
      setPages([]);
    }
    setSearchParams(next, { replace: true });
  }

  function setView(nextView: View) {
    updateFilter("view", nextView === "all" ? "" : nextView);
  }

  const loaded = query.isFetching && !cursor ? [] : pages;
  const rows = useMemo(() => {
    return loaded.filter((action) => {
      if (view === "attention") {
        return action.decision === "deny" || action.outcomeStatus === "failure";
      }
      if (view === "blocked") return action.decision === "deny";
      if (view === "high") {
        return riskRank(riskForTool(action.tool, action.decision).level) >= 2;
      }
      return true;
    });
  }, [loaded, view]);

  const blocked = loaded.filter((action) => action.decision === "deny").length;
  const failed = loaded.filter((action) => action.outcomeStatus === "failure").length;

  return (
    <>
      <PageHeader
        title="Actions"
        subtitle={
          loaded.length
            ? `${loaded.length} in this view · ${blocked} blocked · ${failed} failed outcomes`
            : "Every signed authorization and its linked outcome."
        }
        actions={
          <Link className="tf-btn" to="/keys">Agent keys</Link>
        }
      />

      <Card>
        <div className="tf-saved-views" role="tablist" aria-label="Saved action views">
          {VIEWS.map((item) => (
            <button
              key={item.id}
              className={`tf-saved-view ${view === item.id ? "active" : ""}`}
              onClick={() => setView(item.id)}
              role="tab"
              aria-selected={view === item.id}
            >
              {item.label}
            </button>
          ))}
        </div>

        <div className="tf-actions" style={{ marginBottom: 14 }}>
          <input
            className="tf-input"
            style={{ maxWidth: 200 }}
            placeholder="Filter agent"
            value={agentId}
            onChange={(event) => updateFilter("agentId", event.target.value)}
          />
          <input
            className="tf-input"
            style={{ maxWidth: 220 }}
            placeholder="Filter tool"
            value={tool}
            onChange={(event) => updateFilter("tool", event.target.value)}
          />
          <select
            className="tf-select"
            style={{ maxWidth: 150 }}
            value={decision}
            onChange={(event) => updateFilter("decision", event.target.value)}
          >
            <option value="">Any decision</option>
            <option value="allow">Allow</option>
            <option value="deny">Deny</option>
          </select>
          <select
            className="tf-select"
            style={{ maxWidth: 150 }}
            value={outcome}
            onChange={(event) => updateFilter("outcome", event.target.value)}
          >
            <option value="">Any outcome</option>
            <option value="success">Success</option>
            <option value="failure">Failure</option>
            <option value="denied">Denied</option>
            <option value="timeout">Timeout</option>
            <option value="unknown">Unknown</option>
          </select>
          {agentId || tool || decision || outcome || view !== "all" ? (
            <Button
              variant="ghost"
              onClick={() => {
                setSearchParams({}, { replace: true });
                setCursor(null);
                setPages([]);
              }}
            >
              Clear
            </Button>
          ) : null}
        </div>

        {rows.length === 0 && !query.isLoading ? (
          <EmptyState title={view === "all" ? "No actions match" : "Nothing in this view"}>
            {view === "attention"
              ? "No blocked or failed actions. The control plane is quiet."
              : "Instrument an action or clear the filters. The first action from an agent key will appear here."}
          </EmptyState>
        ) : (
          <table className="tf-table">
            <thead>
              <tr>
                <th>Tool</th>
                <th>Agent / principal</th>
                <th>Risk</th>
                <th>Decision</th>
                <th>Outcome</th>
                <th>Verification</th>
                <th>Policy</th>
                <th>When</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((action) => {
                const risk = riskForTool(action.tool, action.decision);
                return (
                  <tr key={action.actionId}>
                    <td>
                      <Link to={`/actions/${action.actionId}`}>{action.tool}</Link>
                      <div className="tf-mono tf-muted">{shortHash(action.actionId, 8)}</div>
                    </td>
                    <td>
                      <div className="tf-mono">{action.agentId}</div>
                      <div className="tf-muted tf-mono">{action.principalId}</div>
                    </td>
                    <td><RiskBadge level={risk.level} /></td>
                    <td>
                      <Badge tone={action.decision === "allow" ? "ok" : "bad"}>{action.decision}</Badge>
                    </td>
                    <td>
                      <Badge
                        tone={
                          action.outcomeStatus === "success"
                            ? "ok"
                            : action.outcomeStatus
                              ? "warn"
                              : "muted"
                        }
                      >
                        {action.outcomeStatus || "pending"}
                      </Badge>
                    </td>
                    <td>
                      <Badge tone={action.verified ? "ok" : action.outcomeStatus ? "warn" : "muted"}>
                        {action.verified ? "verified" : action.outcomeStatus ? "check" : "unsigned"}
                      </Badge>
                    </td>
                    <td>
                      <span className="tf-mono">{action.policyId || "—"}</span>
                      <span className="tf-muted"> v{action.policyVersion}</span>
                    </td>
                    <td className="tf-muted">{formatDate(action.createdAt)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}

        {query.data?.nextCursor ? (
          <div className="tf-actions" style={{ justifyContent: "center", marginTop: 16 }}>
            <Button onClick={() => setCursor(query.data!.nextCursor)}>Load more</Button>
          </div>
        ) : null}
        {query.isError ? (
          <div className="tf-error">{query.error instanceof Error ? query.error.message : "Failed to load actions"}</div>
        ) : null}
      </Card>
    </>
  );
}
