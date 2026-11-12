import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, environmentQuery, type ActionSummary } from "../api";
import { useWorkspace } from "../App";
import { Badge, Button, Card, ErrorBanner, PageHeader } from "@tessera/ui";

type PolicyMode = "monitor" | "recommend" | "enforce";

interface Constraint {
  type: string;
  field?: string;
  value?: string | number;
  values?: string[];
  prefix?: string;
}

interface Policy {
  id: string;
  version: number;
  name: string;
  mode?: PolicyMode;
  grants: Array<{
    resource: string;
    condition?: string | null;
    constraints?: Constraint[];
  }>;
  fail_open: boolean;
  limits?: Record<string, unknown>;
}

const NEW_POLICY: Policy = {
  id: "refunds",
  version: 1,
  name: "Refunds under $500",
  mode: "enforce",
  grants: [
    {
      resource: "stripe:refunds.create",
      constraints: [{ type: "max_number", field: "amount", value: 500 }],
    },
  ],
  fail_open: false,
};

const MODES: Array<{ id: PolicyMode; label: string; note: string }> = [
  { id: "monitor", label: "Monitor", note: "Observe and mark would-deny; never block." },
  { id: "recommend", label: "Recommend", note: "Allow with an advisory reason; flag for review." },
  { id: "enforce", label: "Enforce", note: "Block violations before a credential is issued." },
];

function resourceForTool(tool: string): string {
  if (tool.includes(":")) return tool;
  const [provider, ...rest] = tool.split(".");
  return `${provider}:${rest.join(".")}`;
}

function matches(pattern: string, resource: string): boolean {
  return pattern === "*" || pattern === resource || (pattern.endsWith("*") && resource.startsWith(pattern.slice(0, -1)));
}

function constraintText(constraint: Constraint): string {
  switch (constraint.type) {
    case "max_number":
      return `${constraint.field} ≤ ${constraint.value}`;
    case "min_number":
      return `${constraint.field} ≥ ${constraint.value}`;
    case "allowlist":
      return `${constraint.field} in [${(constraint.values ?? []).join(", ")}]`;
    case "prefix":
      return `${constraint.field} starts with "${constraint.prefix}"`;
    case "required":
      return `${constraint.field} required`;
    default:
      return constraint.type;
  }
}

export function PoliciesPage() {
  const { environmentId } = useWorkspace();
  const queryClient = useQueryClient();
  const [selected, setSelected] = useState<string | null>(null);
  const [draft, setDraft] = useState(JSON.stringify(NEW_POLICY, null, 2));
  const [notes, setNotes] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);

  const policies = useQuery({
    queryKey: ["policies", environmentId],
    queryFn: () => api<{ items: Policy[] }>(`/v1/policies${environmentQuery(environmentId)}`),
    enabled: Boolean(environmentId),
  });
  const actions = useQuery({
    queryKey: ["actions", environmentId, "policies"],
    queryFn: () =>
      api<{ items: ActionSummary[] }>(
        `/v1/actions?limit=100${environmentId ? `&environmentId=${environmentId}` : ""}`,
      ),
    enabled: Boolean(environmentId),
  });

  useEffect(() => {
    if (selected) return;
    const first = policies.data?.items[0];
    if (first) {
      setSelected(first.id);
      setDraft(JSON.stringify(first, null, 2));
    }
  }, [policies.data, selected]);

  const parsed = useMemo<Policy | null>(() => {
    try {
      return JSON.parse(draft) as Policy;
    } catch {
      return null;
    }
  }, [draft]);

  const save = useMutation({
    mutationFn: async (body: string) => {
      const policy = JSON.parse(body) as Policy;
      return api(`/v1/policies/${encodeURIComponent(policy.id)}${environmentQuery(environmentId)}`, {
        method: "PUT",
        body: JSON.stringify(policy),
      });
    },
    onSuccess: async () => {
      setError(null);
      await queryClient.invalidateQueries({ queryKey: ["policies"] });
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  const remove = useMutation({
    mutationFn: (id: string) => api(`/v1/policies/${encodeURIComponent(id)}${environmentQuery(environmentId)}`, { method: "DELETE" }),
    onSuccess: async () => {
      setSelected(null);
      setDraft(JSON.stringify(NEW_POLICY, null, 2));
      await queryClient.invalidateQueries({ queryKey: ["policies"] });
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  const propose = useMutation({
    mutationFn: () => api<{ policy: Policy; notes?: string[] }>(`/v1/policies/propose${environmentQuery(environmentId)}`),
    onSuccess: (data) => {
      setSelected(data.policy.id);
      setDraft(JSON.stringify(data.policy, null, 2));
      setNotes(data.notes ?? []);
      setError(null);
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  function selectPolicy(policy: Policy) {
    setSelected(policy.id);
    setDraft(JSON.stringify(policy, null, 2));
    setNotes([]);
  }

  function setMode(mode: PolicyMode) {
    if (!parsed) return;
    if ((parsed.mode ?? "enforce") === mode) return;
    const next = { ...parsed, mode, version: Number(parsed.version) + 1 };
    const nextDraft = JSON.stringify(next, null, 2);
    setDraft(nextDraft);
    save.mutate(nextDraft);
  }

  const mode = parsed?.mode ?? "enforce";
  const recent = actions.data?.items ?? [];
  const coverage = parsed
    ? recent.filter((action) =>
        parsed.grants.some((grant) => matches(grant.resource, resourceForTool(action.tool))),
      ).length
    : 0;

  return (
    <>
      <PageHeader
        title="Policies"
        subtitle="Write intent, prove it against traffic, then tighten the boundary."
        actions={
          <>
            <Button onClick={() => propose.mutate()} disabled={propose.isPending || !environmentId}>
              {propose.isPending ? "Proposing…" : "Propose from traffic"}
            </Button>
            <Button
              variant="primary"
              onClick={() => save.mutate(draft)}
              disabled={save.isPending || !environmentId || !parsed}
            >
              {save.isPending ? "Saving…" : "Save policy"}
            </Button>
          </>
        }
      />
      <ErrorBanner message={error} />

      <div className="tf-grid" style={{ gridTemplateColumns: "280px 1fr", alignItems: "start" }}>
        <Card>
          <div className="tf-actions" style={{ justifyContent: "space-between", marginBottom: 8 }}>
            <h2 style={{ margin: 0, fontSize: 18 }}>Policies</h2>
            <Button
              variant="ghost"
              onClick={() => {
                setSelected(null);
                setDraft(JSON.stringify({ ...NEW_POLICY, id: `policy-${Date.now()}` }, null, 2));
              }}
            >
              New
            </Button>
          </div>
          <div className="tf-list">
            {policies.data?.items.length ? (
              policies.data.items.map((policy) => (
                <button
                  key={policy.id}
                  className={`tf-policy-item ${selected === policy.id ? "active" : ""}`}
                  onClick={() => selectPolicy(policy)}
                >
                  <div>
                    <strong>{policy.name}</strong>
                    <div className="tf-muted">{policy.id} · v{policy.version}</div>
                  </div>
                  <Badge tone={(policy.mode ?? "enforce") === "enforce" ? "ok" : "warn"}>
                    {policy.mode ?? "enforce"}
                  </Badge>
                </button>
              ))
            ) : (
              <p className="tf-muted">No policies yet. Create one or propose from traffic.</p>
            )}
          </div>
        </Card>

        <div className="tf-grid" style={{ gap: 16 }}>
          {parsed ? (
            <>
              <Card>
                <div className="tf-actions" style={{ justifyContent: "space-between", alignItems: "flex-start" }}>
                  <div>
                    <div className="tf-kpi-label">Trust ladder</div>
                    <h2 style={{ margin: "5px 0 4px", fontSize: 22 }}>{parsed.name}</h2>
                    <p className="tf-muted" style={{ margin: 0 }}>
                      {MODES.find((item) => item.id === mode)?.note}
                    </p>
                  </div>
                  <Badge tone={mode === "enforce" ? "ok" : "warn"}>{mode}</Badge>
                </div>
                <div className="tf-ladder">
                  {MODES.map((item, index) => (
                    <button
                      key={item.id}
                      className={`tf-ladder-step ${mode === item.id ? "active" : ""}`}
                      onClick={() => setMode(item.id)}
                      disabled={save.isPending}
                    >
                      <span className="tf-ladder-number">{index + 1}</span>
                      <span>
                        <strong>{item.label}</strong>
                        <small>{item.note}</small>
                      </span>
                    </button>
                  ))}
                </div>
                <p className="tf-muted" style={{ margin: "12px 0 0", fontSize: 11 }}>
                  Changing the posture creates a new immutable policy version. Shadow modes evaluate against real
                  traffic but do not block.
                </p>
              </Card>

              <div className="tf-grid tf-grid-3">
                <Card>
                  <div className="tf-kpi-label">Governed actions</div>
                  <div className="tf-kpi" style={{ marginTop: 7 }}>{coverage}</div>
                  <div className="tf-muted">of {recent.length} recent actions</div>
                </Card>
                <Card>
                  <div className="tf-kpi-label">Rules</div>
                  <div className="tf-kpi" style={{ marginTop: 7 }}>{parsed.grants.length}</div>
                  <div className="tf-muted">resource grants</div>
                </Card>
                <Card>
                  <div className="tf-kpi-label">Version</div>
                  <div className="tf-kpi" style={{ marginTop: 7 }}>v{parsed.version}</div>
                  <div className="tf-muted">immutable history</div>
                </Card>
              </div>

              <Card>
                <div className="tf-actions" style={{ justifyContent: "space-between", marginBottom: 12 }}>
                  <h2 style={{ margin: 0, fontSize: 18 }}>Rules</h2>
                  <Button variant="ghost" onClick={() => setShowAdvanced((value) => !value)}>
                    {showAdvanced ? "Hide JSON" : "Advanced JSON"}
                  </Button>
                </div>
                <div className="tf-rule-list">
                  {parsed.grants.map((grant, index) => (
                    <div className="tf-rule" key={`${grant.resource}-${index}`}>
                      <div>
                        <span className="tf-rule-resource">{grant.resource}</span>
                        {grant.condition ? <span className="tf-muted"> · CEL: {grant.condition}</span> : null}
                      </div>
                      <div className="tf-rule-constraints">
                        {grant.constraints?.length
                          ? grant.constraints.map((constraint, constraintIndex) => (
                              <span className="tf-rule-chip" key={constraintIndex}>{constraintText(constraint)}</span>
                            ))
                          : <span className="tf-muted">No constraints</span>}
                      </div>
                    </div>
                  ))}
                </div>
                {showAdvanced ? (
                  <textarea
                    className="tf-textarea"
                    style={{ marginTop: 14 }}
                    value={draft}
                    onChange={(event) => setDraft(event.target.value)}
                    spellCheck={false}
                  />
                ) : null}
              </Card>

              {notes.length ? (
                <Card>
                  <h2 style={{ margin: 0, fontSize: 18 }}>Proposal notes</h2>
                  <ul className="tf-muted" style={{ margin: "10px 0 0", paddingLeft: 18 }}>
                    {notes.map((note, index) => <li key={index}>{note}</li>)}
                  </ul>
                </Card>
              ) : null}

              <div className="tf-actions" style={{ justifyContent: "flex-end" }}>
                {selected ? (
                  <Button variant="danger" onClick={() => remove.mutate(selected)} disabled={remove.isPending}>
                    Delete policy
                  </Button>
                ) : null}
              </div>
            </>
          ) : (
            <Card>
              <p className="tf-muted">The policy JSON is invalid. Open the advanced editor and fix the document.</p>
            </Card>
          )}
        </div>
      </div>
    </>
  );
}
