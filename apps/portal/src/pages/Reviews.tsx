import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { api } from "../api";
import { Badge, Button, Card, EmptyState, ErrorBanner, ErrorState, PageHeader, Skeleton, formatDate } from "@tessera/ui";

interface Review {
  id: string;
  action_id: string;
  status: "pending" | "approved" | "rejected";
  reason: string | null;
  resolution_note: string | null;
  created_at: string;
  resolved_at: string | null;
  agent_id: string;
  principal_id: string;
  tool: string;
  decision: string;
  outcome_status: string | null;
  action_created_at: string;
}

type Filter = "pending" | "approved" | "rejected" | "all";

const FILTERS: Array<{ id: Filter; label: string }> = [
  { id: "pending", label: "Pending" },
  { id: "approved", label: "Approved" },
  { id: "rejected", label: "Rejected" },
  { id: "all", label: "All" },
];

export function ReviewsPage() {
  const queryClient = useQueryClient();
  const [filter, setFilter] = useState<Filter>("pending");
  const [error, setError] = useState<string | null>(null);

  const reviews = useQuery({
    queryKey: ["reviews", filter],
    queryFn: () => api<{ items: Review[] }>(`/v1/reviews?status=${filter}`),
  });

  const decide = useMutation({
    mutationFn: ({ id, decision }: { id: string; decision: "approve" | "reject" }) =>
      api(`/v1/reviews/${id}/decision`, {
        method: "POST",
        body: JSON.stringify({ decision }),
      }),
    onSuccess: async () => {
      setError(null);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["reviews"] }),
        queryClient.invalidateQueries({ queryKey: ["actions"] }),
        queryClient.invalidateQueries({ queryKey: ["action"] }),
      ]);
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  return (
    <>
      <PageHeader
        title="Reviews"
        subtitle="Actions waiting for a human decision before they leave the evidence trail."
        actions={<Link className="tf-btn" to="/actions?view=attention">View attention queue</Link>}
      />
      <ErrorBanner message={error} />
      <Card>
        <div className="tf-saved-views" role="tablist" aria-label="Review filters">
          {FILTERS.map((item) => (
            <button
              key={item.id}
              className={`tf-saved-view ${filter === item.id ? "active" : ""}`}
              onClick={() => setFilter(item.id)}
              role="tab"
              aria-selected={filter === item.id}
            >
              {item.label}
            </button>
          ))}
        </div>

        {reviews.isLoading ? (
          <div className="tf-review-list">
            {Array.from({ length: 3 }).map((_, index) => (
              <div className="tf-review-item" key={index}>
                <div className="tf-review-main">
                  <Skeleton width="32%" height={14} />
                  <Skeleton width="64%" height={10} style={{ marginTop: 10 }} />
                  <Skeleton width="82%" height={10} style={{ marginTop: 10 }} />
                </div>
              </div>
            ))}
          </div>
        ) : reviews.isError ? (
          <ErrorState
            title="Reviews are unavailable"
            message={reviews.error instanceof Error ? reviews.error.message : "Could not load the review queue."}
            action={<Button onClick={() => reviews.refetch()}>Retry</Button>}
          />
        ) : reviews.data?.items.length ? (
          <div className="tf-review-list">
            {reviews.data.items.map((review) => (
              <div className="tf-review-item" key={review.id}>
                <div className="tf-review-main">
                  <div className="tf-review-title">
                    <Link to={`/actions/${review.action_id}`}>{review.tool}</Link>
                    <Badge tone={review.status === "pending" ? "warn" : review.status === "approved" ? "ok" : "bad"}>
                      {review.status}
                    </Badge>
                  </div>
                  <div className="tf-muted">
                    {review.agent_id} · {review.principal_id} · action {shortId(review.action_id)}
                  </div>
                  <div className="tf-review-reason">{review.reason ?? "No reason supplied"}</div>
                  <div className="tf-muted tf-mono">
                    requested {formatDate(review.created_at)}
                    {review.resolved_at ? ` · resolved ${formatDate(review.resolved_at)}` : ""}
                  </div>
                </div>
                <div className="tf-review-actions">
                  {review.status === "pending" ? (
                    <>
                      <Button
                        variant="primary"
                        onClick={() => decide.mutate({ id: review.id, decision: "approve" })}
                        disabled={decide.isPending}
                      >
                        Approve
                      </Button>
                      <Button
                        variant="danger"
                        onClick={() => decide.mutate({ id: review.id, decision: "reject" })}
                        disabled={decide.isPending}
                      >
                        Reject
                      </Button>
                    </>
                  ) : (
                    <Link className="tf-btn ghost" to={`/actions/${review.action_id}`}>Open action</Link>
                  )}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState title={filter === "pending" ? "No pending reviews" : `No ${filter} reviews`}>
            {filter === "pending"
              ? "High-risk actions can be sent here from the action detail page."
              : "Resolved reviews will appear here with their decision trail."}
          </EmptyState>
        )}
      </Card>
    </>
  );
}

function shortId(value: string): string {
  return value.length > 14 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value;
}
