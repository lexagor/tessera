import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, environmentQuery } from "../api";
import { useWorkspace } from "../App";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorBanner,
  PageHeader,
  formatDate,
} from "@tessera/ui";
import { useState } from "react";

interface EvidencePack {
  id: string;
  environment_id: string;
  status: string;
  filters: Record<string, unknown>;
  created_at: string;
  expires_at: string | null;
}

export function EvidencePage() {
  const { environmentId } = useWorkspace();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const packs = useQuery({
    queryKey: ["evidence-packs", environmentId],
    queryFn: () =>
      api<{ items: EvidencePack[] }>(`/v1/evidence-packs${environmentQuery(environmentId)}`),
    enabled: Boolean(environmentId),
  });
  const create = useMutation({
    mutationFn: () => api(`/v1/evidence-packs${environmentQuery(environmentId)}`, { method: "POST", body: "{}" }),
    onSuccess: async () => {
      setError(null);
      await queryClient.invalidateQueries({ queryKey: ["evidence-packs"] });
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  return (
    <>
      <PageHeader
        title="Evidence"
        subtitle="Signed archives for security reviews, audits, and customer requests."
        actions={
          <Button
            variant="primary"
            onClick={() => create.mutate()}
            disabled={!environmentId || create.isPending}
          >
            {create.isPending ? "Building…" : "Build evidence pack"}
          </Button>
        }
      />
      <ErrorBanner message={error} />
      <Card>
        {packs.data?.items.length ? (
          <table className="tf-table">
            <thead>
              <tr><th>Created</th><th>Status</th><th>Expires</th><th /></tr>
            </thead>
            <tbody>
              {packs.data.items.map((pack) => (
                <tr key={pack.id}>
                  <td>{formatDate(pack.created_at)}</td>
                  <td><Badge tone={pack.status === "ready" ? "ok" : pack.status === "failed" ? "bad" : "warn"}>{pack.status}</Badge></td>
                  <td className="tf-muted">{formatDate(pack.expires_at)}</td>
                  <td>
                    {pack.status === "ready" ? (
                      <a className="tf-btn ghost" href={`/v1/evidence-packs/${pack.id}/download`}>
                        Download
                      </a>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <EmptyState title="No evidence packs yet">
            Build a signed archive containing receipts, policy versions, key events, anchors, and
            the control mapping.
          </EmptyState>
        )}
      </Card>
    </>
  );
}
