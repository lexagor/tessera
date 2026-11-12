import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, environmentQuery } from "../api";
import { useWorkspace } from "../App";
import { Badge, Button, Card, ErrorBanner, PageHeader } from "@tessera/ui";

interface Policy {
  id: string;
  version: number;
  name: string;
  grants: Array<{ resource: string; condition?: string | null }>;
  fail_open: boolean;
}

const NEW_POLICY = {
  id: "refunds",
  version: 1,
  name: "Refunds under $50",
  grants: [
    {
      resource: "stripe:refunds.create",
      constraints: [{ type: "max_number", field: "amount", value: 5000 }],
    },
  ],
  fail_open: false,
};

export function PoliciesPage() {
  const { environmentId } = useWorkspace();
  const queryClient = useQueryClient();
  const [selected, setSelected] = useState<string | null>(null);
  const [draft, setDraft] = useState(JSON.stringify(NEW_POLICY, null, 2));
  const [notes, setNotes] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);

  const policies = useQuery({
    queryKey: ["policies", environmentId],
    queryFn: () => api<{ items: Policy[] }>(`/v1/policies${environmentQuery(environmentId)}`),
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

  const save = useMutation({
    mutationFn: async () => {
      const policy = JSON.parse(draft) as Policy;
      const id = policy.id;
      return api(`/v1/policies/${encodeURIComponent(id)}${environmentQuery(environmentId)}`, {
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

  return (
    <>
      <PageHeader
        title="Policies"
        subtitle="Per-action authorization. Policy versions are immutable; bump the version when content changes."
        actions={
          <>
            <Button onClick={() => propose.mutate()} disabled={propose.isPending || !environmentId}>
              {propose.isPending ? "Proposing…" : "Propose from traffic"}
            </Button>
            <Button
              variant="primary"
              onClick={() => save.mutate()}
              disabled={save.isPending || !environmentId}
            >
              {save.isPending ? "Saving…" : "Save policy"}
            </Button>
          </>
        }
      />
      <ErrorBanner message={error} />
      <div className="tf-grid" style={{ gridTemplateColumns: "280px 1fr" }}>
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
                  className="tf-list-row"
                  style={{ background: "none", border: 0, color: "inherit", textAlign: "left", cursor: "pointer" }}
                  onClick={() => {
                    setSelected(policy.id);
                    setDraft(JSON.stringify(policy, null, 2));
                    setNotes([]);
                  }}
                >
                  <div>
                    <strong>{policy.id}</strong>
                    <div className="tf-muted">{policy.name} · v{policy.version}</div>
                  </div>
                  <Badge tone={selected === policy.id ? "ok" : "muted"}>{policy.grants.length} grants</Badge>
                </button>
              ))
            ) : (
              <p className="tf-muted">No policies yet.</p>
            )}
          </div>
        </Card>

        <Card>
          <div className="tf-actions" style={{ justifyContent: "space-between" }}>
            <h2 style={{ margin: 0, fontSize: 18 }}>{selected ? selected : "New policy"}</h2>
            {selected ? (
              <Button variant="danger" onClick={() => remove.mutate(selected)} disabled={remove.isPending}>
                Delete
              </Button>
            ) : null}
          </div>
          <textarea
            className="tf-textarea"
            style={{ marginTop: 12 }}
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            spellCheck={false}
          />
          {notes.length ? (
            <ul className="tf-muted" style={{ marginTop: 12 }}>
              {notes.map((note, index) => <li key={index}>{note}</li>)}
            </ul>
          ) : null}
        </Card>
      </div>
    </>
  );
}
