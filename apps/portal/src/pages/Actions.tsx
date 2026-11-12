import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";

import { api, type ActionSummary } from "../api";
import { useWorkspace } from "../App";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorState,
  Modal,
  PageHeader,
  SkeletonTable,
  formatDate,
  shortHash,
} from "@tessera/ui";
import { RiskBadge } from "../components/Charts";
import { TimeRangePicker } from "../components/TimeRange";
import { riskForTool, riskRank } from "../lib/risk";
import { isTimeRange, rangeWindow, type TimeRange } from "../lib/time";

type View = "all" | "attention" | "blocked" | "high" | "unverified";

const VIEWS: Array<{ id: View; label: string }> = [
  { id: "all", label: "All actions" },
  { id: "attention", label: "Needs attention" },
  { id: "blocked", label: "Blocked" },
  { id: "high", label: "High risk" },
  { id: "unverified", label: "Unverified" },
];

interface SavedActionView {
  id: string;
  name: string;
  filters: {
    agentId: string;
    tool: string;
    decision: string;
    outcome: string;
    view: View;
    range: TimeRange;
  };
}

function savedViewsKey(environmentId: string): string {
  return `tessera.actionViews.${environmentId}`;
}

function loadSavedViews(environmentId: string): SavedActionView[] {
  try {
    const raw = window.localStorage.getItem(savedViewsKey(environmentId));
    return raw ? (JSON.parse(raw) as SavedActionView[]) : [];
  } catch {
    return [];
  }
}

export function ActionsPage() {
  const { environmentId } = useWorkspace();
  const [searchParams, setSearchParams] = useSearchParams();
  const agentId = searchParams.get("agentId") ?? "";
  const tool = searchParams.get("tool") ?? "";
  const decision = searchParams.get("decision") ?? "";
  const outcome = searchParams.get("outcome") ?? "";
  const view = (searchParams.get("view") as View | null) ?? "all";
  const rangeParam = searchParams.get("range");
  const range: TimeRange = isTimeRange(rangeParam) ? rangeParam : "14d";
  const [cursor, setCursor] = useState<string | null>(null);
  const [pages, setPages] = useState<ActionSummary[]>([]);
  const [saved, setSaved] = useState<SavedActionView[]>(() => loadSavedViews(environmentId));
  const [saveOpen, setSaveOpen] = useState(false);
  const [saveName, setSaveName] = useState("");

  useEffect(() => {
    setSaved(loadSavedViews(environmentId));
  }, [environmentId]);

  const query = useQuery({
    queryKey: ["actions", environmentId, agentId, tool, decision, outcome, view, range, cursor],
    queryFn: async () => {
      const params = new URLSearchParams();
      const window = rangeWindow(range);
      params.set("limit", view === "all" ? "25" : "100");
      params.set("since", window.since);
      params.set("until", window.until);
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
      if (view === "unverified") {
        return Boolean(action.outcomeStatus) && action.verified !== true;
      }
      return true;
    });
  }, [loaded, view]);

  const blocked = loaded.filter((action) => action.decision === "deny").length;
  const failed = loaded.filter((action) => action.outcomeStatus === "failure").length;
  const loading = !cursor && query.isFetching;
  const hasFilters = Boolean(agentId || tool || decision || outcome || view !== "all" || range !== "14d");

  function setRange(next: TimeRange) {
    updateFilter("range", next);
  }

  function applySavedView(savedView: SavedActionView) {
    const next = new URLSearchParams();
    const filters = savedView.filters;
    if (filters.agentId) next.set("agentId", filters.agentId);
    if (filters.tool) next.set("tool", filters.tool);
    if (filters.decision) next.set("decision", filters.decision);
    if (filters.outcome) next.set("outcome", filters.outcome);
    if (filters.view !== "all") next.set("view", filters.view);
    if (filters.range !== "14d") next.set("range", filters.range);
    setSearchParams(next, { replace: true });
    setCursor(null);
    setPages([]);
  }

  function saveView() {
    const name = saveName.trim();
    if (!name) return;
    const savedView: SavedActionView = {
      id: `view_${Date.now().toString(36)}`,
      name,
      filters: { agentId, tool, decision, outcome, view, range },
    };
    const next = [...saved, savedView];
    setSaved(next);
    try {
      window.localStorage.setItem(savedViewsKey(environmentId), JSON.stringify(next));
    } catch {
      /* storage can be unavailable in private contexts */
    }
    setSaveOpen(false);
    setSaveName("");
  }

  function removeSavedView(id: string) {
    const next = saved.filter((item) => item.id !== id);
    setSaved(next);
    try {
      window.localStorage.setItem(savedViewsKey(environmentId), JSON.stringify(next));
    } catch {
      /* ignore */
    }
  }

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
          <>
            <TimeRangePicker value={range} onChange={setRange} label="Action time range" />
            <Link className="tf-btn" to="/keys">Agent keys</Link>
          </>
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
        <div className="tf-custom-views">
          <span className="tf-kpi-label">Your views</span>
          {saved.map((item) => (
            <span className="tf-custom-view" key={item.id}>
              <button onClick={() => applySavedView(item)}>{item.name}</button>
              <button className="tf-custom-view-remove" onClick={() => removeSavedView(item.id)} aria-label={`Delete saved view ${item.name}`}>×</button>
            </span>
          ))}
          <Button variant="ghost" onClick={() => setSaveOpen(true)}>Save current view</Button>
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
          {agentId || tool || decision || outcome || view !== "all" || range !== "14d" ? (
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

        {loading ? (
          <SkeletonTable rows={6} columns={8} />
        ) : query.isError ? (
          <ErrorState
            title="Actions are unavailable"
            message={query.error instanceof Error ? query.error.message : "Failed to load actions"}
            action={<Button onClick={() => query.refetch()}>Retry</Button>}
          />
        ) : rows.length === 0 ? (
          <EmptyState
            title={view === "all" && !hasFilters ? "No actions in this window" : "No actions match"}
            action={
              hasFilters ? (
                <Button
                  variant="primary"
                  onClick={() => {
                    setSearchParams({}, { replace: true });
                    setCursor(null);
                    setPages([]);
                  }}
                >
                  Clear filters
                </Button>
              ) : (
                <Link className="tf-btn primary" to="/keys">Create an agent key</Link>
              )
            }
          >
            {view === "attention"
              ? "No blocked or failed actions. The control plane is quiet."
              : view === "unverified"
                ? "Every completed action in this window has passed independent verification."
                : view === "blocked"
                  ? "No policy-denied actions in this window."
                  : "Instrument an action or widen the time range. The first action from an agent key will appear here."}
          </EmptyState>
        ) : (
          <div className="tf-table-wrap">
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
          </div>
        )}

        {query.data?.nextCursor ? (
          <div className="tf-actions" style={{ justifyContent: "center", marginTop: 16 }}>
            <Button onClick={() => setCursor(query.data!.nextCursor)}>Load more</Button>
          </div>
        ) : null}
      </Card>

      {saveOpen ? (
        <Modal title="Save action view" onClose={() => setSaveOpen(false)}>
          <p>Save the current filters and time range as a reusable view in this environment.</p>
          <label className="tf-field">
            View name
            <input
              className="tf-input"
              value={saveName}
              onChange={(event) => setSaveName(event.target.value)}
              placeholder="High-risk Stripe actions"
              autoFocus
              onKeyDown={(event) => {
                if (event.key === "Enter") saveView();
              }}
            />
          </label>
          <div className="tf-modal-actions">
            <Button variant="ghost" onClick={() => setSaveOpen(false)}>Cancel</Button>
            <Button variant="primary" onClick={saveView} disabled={!saveName.trim()}>Save view</Button>
          </div>
        </Modal>
      ) : null}
    </>
  );
}
