import { useQuery } from "@tanstack/react-query";

import { api } from "../api";
import { useWorkspace } from "../App";
import { Badge, Card, EmptyState, PageHeader, formatDate, shortHash } from "@tessera/ui";

interface TransitionEvent {
  id: string;
  kind: string;
  key_id: string;
  key_name: string;
  at: string;
  event_hash: string;
  details: {
    transitionType?: string;
    target?: string;
    reason?: string | null;
    provider?: string | null;
    before?: unknown;
    after?: unknown;
  };
}

export function TransitionsPage() {
  const { environmentId } = useWorkspace();
  const query = useQuery({
    queryKey: ["transitions", environmentId],
    queryFn: () =>
      api<{ items: TransitionEvent[]; verified?: boolean; signaturesValid?: boolean }>(
        "/v1/transitions",
      ),
    enabled: Boolean(environmentId),
  });

  const items = query.data?.items ?? [];
  return (
    <>
      <PageHeader
        title="Authority transitions"
        subtitle="Signed, hash-linked revocations, rotations, and scope changes."
        actions={
          query.data?.verified === false ? (
            <Badge tone="bad">ledger invalid</Badge>
          ) : (
            <Badge tone="ok">ledger verified</Badge>
          )
        }
      />
      <Card>
        {items.length ? (
          <table className="tf-table">
            <thead>
              <tr>
                <th>Transition</th>
                <th>Target</th>
                <th>Reason</th>
                <th>When</th>
                <th>Event hash</th>
              </tr>
            </thead>
            <tbody>
              {items.map((event) => (
                <tr key={event.id}>
                  <td>
                    <Badge tone={event.kind === "authority.revoked" ? "bad" : "warn"}>
                      {event.details.transitionType ?? event.kind}
                    </Badge>
                  </td>
                  <td className="tf-mono">{event.details.target ?? event.key_name ?? event.key_id}</td>
                  <td className="tf-muted">{event.details.reason ?? "—"}</td>
                  <td>{formatDate(event.at)}</td>
                  <td className="tf-mono">{shortHash(event.event_hash, 14)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <EmptyState title="No authority transitions">
            Revoke a grant or agent, rotate a key, or narrow a key scope. The signed event appears
            here and in the evidence pack.
          </EmptyState>
        )}
      </Card>
    </>
  );
}
