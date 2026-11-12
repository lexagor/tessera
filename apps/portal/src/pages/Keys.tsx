import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, environmentQuery, type AgentKey } from "../api";
import { useWorkspace } from "../App";
import {
  Badge,
  Button,
  Card,
  CopyRow,
  EmptyState,
  ErrorBanner,
  ErrorState,
  PageHeader,
  SkeletonTable,
  formatDate,
} from "@tessera/ui";

export function KeysPage() {
  const { environmentId } = useWorkspace();
  const queryClient = useQueryClient();
  const [name, setName] = useState("agent-prod");
  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const keys = useQuery({
    queryKey: ["agent-keys", environmentId],
    queryFn: () =>
      api<{ items: AgentKey[] }>(`/v1/agent-keys${environmentQuery(environmentId)}`),
    enabled: Boolean(environmentId),
  });

  const create = useMutation({
    mutationFn: () =>
      api<{ key: string }>(`/v1/agent-keys${environmentQuery(environmentId)}`, {
        method: "POST",
        body: JSON.stringify({ name }),
      }),
    onSuccess: async (data) => {
      setCreatedKey(data.key);
      setError(null);
      await queryClient.invalidateQueries({ queryKey: ["agent-keys"] });
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  const revoke = useMutation({
    mutationFn: (id: string) => api(`/v1/agent-keys/${id}`, { method: "DELETE" }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["agent-keys"] });
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  return (
    <>
      <PageHeader
        title="Agent keys"
        subtitle="API keys your agents use. Keys are scoped to the selected environment."
      />
      <ErrorBanner message={error} />

      <Card style={{ marginBottom: 16 }}>
        <div className="tf-actions">
          <input
            className="tf-input"
            style={{ maxWidth: 260 }}
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="Key name"
          />
          <Button
            variant="primary"
            onClick={() => create.mutate()}
            disabled={create.isPending || !name.trim()}
          >
            {create.isPending ? "Creating…" : "Create agent key"}
          </Button>
        </div>
        {createdKey ? (
          <div style={{ marginTop: 16 }}>
            <p className="tf-muted" style={{ marginBottom: 6 }}>
              Store this key now; it will not be shown again.
            </p>
            <CopyRow value={createdKey} />
          </div>
        ) : null}
      </Card>

      <Card>
        {keys.isLoading ? (
          <SkeletonTable rows={4} columns={6} />
        ) : keys.isError ? (
          <ErrorState
            title="Agent keys are unavailable"
            message={keys.error instanceof Error ? keys.error.message : "Could not load agent keys."}
            action={<Button onClick={() => keys.refetch()}>Retry</Button>}
          />
        ) : keys.data?.items.length ? (
          <div className="tf-table-wrap">
          <table className="tf-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Prefix</th>
                <th>Created</th>
                <th>Last used</th>
                <th>Authority</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {keys.data.items.map((key) => (
                <tr key={key.id}>
                  <td>{key.name}</td>
                  <td className="tf-mono">{key.prefix}…</td>
                  <td className="tf-muted">{formatDate(key.created_at)}</td>
                  <td className="tf-muted">{formatDate(key.last_used_at)}</td>
                  <td>
                    <Badge tone={key.delegation_mode === "caller" ? "warn" : "ok"}>
                      {key.delegation_mode === "owner"
                        ? "owner-bound"
                        : key.delegation_mode === "token"
                          ? "per-call token"
                          : "caller-asserted"}
                    </Badge>
                    {key.delegated_email ? (
                      <div className="tf-muted" style={{ marginTop: 4 }}>{key.delegated_email}</div>
                    ) : null}
                  </td>
                  <td>
                    <Badge tone={key.revoked_at ? "bad" : "ok"}>
                      {key.revoked_at ? "revoked" : "active"}
                    </Badge>
                  </td>
                  <td>
                    {!key.revoked_at ? (
                      <Button
                        variant="danger"
                        onClick={() => revoke.mutate(key.id)}
                        disabled={revoke.isPending}
                      >
                        Revoke
                      </Button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        ) : (
          <EmptyState title="No agent keys yet">
            Create a key, then use it from the SDK or MCP adapter.
          </EmptyState>
        )}
      </Card>
    </>
  );
}
