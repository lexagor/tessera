import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, type Usage } from "../api";
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

interface BillingState {
  plan: string;
  status: string;
  customerId: string | null;
  subscriptionId: string | null;
  currentPeriodEnd: string | null;
  cancelAtPeriodEnd: boolean;
  usage: { used: number; limit: number };
  stripeConfigured: boolean;
}

interface AuditEvent {
  id: string;
  actor_type: string;
  action: string;
  target: string | null;
  created_at: string;
}

export function SettingsPage() {
  const { me, environmentId, refresh } = useWorkspace();
  const queryClient = useQueryClient();
  const [name, setName] = useState(me.org.name);
  const [envName, setEnvName] = useState("");
  const [webhookUrl, setWebhookUrl] = useState("");
  const [webhookSecret, setWebhookSecret] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const usage = useQuery({
    queryKey: ["usage", environmentId],
    queryFn: () => api<Usage>(`/v1/usage?environmentId=${environmentId}`),
    enabled: Boolean(environmentId),
  });
  const audit = useQuery({
    queryKey: ["audit"],
    queryFn: () => api<{ items: AuditEvent[] }>("/v1/audit"),
  });
  const billing = useQuery({
    queryKey: ["billing"],
    queryFn: () => api<BillingState>("/v1/billing"),
  });
  const webhooks = useQuery({
    queryKey: ["webhooks"],
    queryFn: () =>
      api<{ items: Array<{ id: string; url: string; events: string[]; active: boolean; created_at: string }> }>(
        "/v1/webhooks",
      ),
  });
  const deliveries = useQuery({
    queryKey: ["webhook-deliveries"],
    queryFn: () =>
      api<{ items: Array<{ id: string; event: string; status: string; attempts: number; last_error: string | null; created_at: string }> }>(
        "/v1/webhook-deliveries",
      ),
  });

  const saveOrg = useMutation({
    mutationFn: () =>
      api("/v1/org", { method: "PATCH", body: JSON.stringify({ name }) }),
    onSuccess: async () => {
      setError(null);
      refresh();
      await queryClient.invalidateQueries();
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  const createEnvironment = useMutation({
    mutationFn: () =>
      api("/v1/environments", { method: "POST", body: JSON.stringify({ name: envName }) }),
    onSuccess: async () => {
      setEnvName("");
      setError(null);
      refresh();
      await queryClient.invalidateQueries();
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  const createWebhook = useMutation({
    mutationFn: () =>
      api<{ secret: string }>("/v1/webhooks", {
        method: "POST",
        body: JSON.stringify({ url: webhookUrl, events: [] }),
      }),
    onSuccess: async (data) => {
      setWebhookSecret(data.secret);
      setWebhookUrl("");
      setError(null);
      await queryClient.invalidateQueries({ queryKey: ["webhooks"] });
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  const checkout = useMutation({
    mutationFn: (plan: "team" | "growth") =>
      api<{ url: string }>("/v1/billing/checkout", {
        method: "POST",
        body: JSON.stringify({ plan }),
      }),
    onSuccess: (data) => {
      if (data.url) window.location.href = data.url;
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  const portal = useMutation({
    mutationFn: () => api<{ url: string }>("/v1/billing/portal", { method: "POST", body: "{}" }),
    onSuccess: (data) => {
      if (data.url) window.location.href = data.url;
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  const removeWebhook = useMutation({
    mutationFn: (id: string) => api(`/v1/webhooks/${id}`, { method: "DELETE" }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["webhooks"] });
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  return (
    <>
      <PageHeader title="Settings" subtitle="Organization, environments, usage, webhooks, and audit." />
      <ErrorBanner message={error} />

      <div className="tf-grid" style={{ gridTemplateColumns: "1fr 1fr" }}>
        <Card>
          <h2 style={{ margin: 0, fontSize: 18 }}>Organization</h2>
          <div className="tf-field" style={{ marginTop: 12 }}>
            Workspace name
            <input className="tf-input" value={name} onChange={(event) => setName(event.target.value)} />
          </div>
          <div className="tf-actions" style={{ marginTop: 12 }}>
            <Button variant="primary" onClick={() => saveOrg.mutate()} disabled={saveOrg.isPending || !name.trim()}>
              {saveOrg.isPending ? "Saving…" : "Save"}
            </Button>
            <Badge tone="muted">{me.org.plan} plan</Badge>
          </div>
        </Card>

        <Card>
          <h2 style={{ margin: 0, fontSize: 18 }}>Environments</h2>
          <div className="tf-list" style={{ marginTop: 10 }}>
            {me.environments.map((environment) => (
              <div className="tf-list-row" key={environment.id}>
                <div>
                  <strong>{environment.name}</strong>
                  <div className="tf-mono tf-muted">{environment.broker_tenant}</div>
                </div>
                {environment.id === environmentId ? <Badge tone="ok">active</Badge> : null}
              </div>
            ))}
          </div>
          {me.role === "owner" || me.role === "admin" ? (
            <div className="tf-actions" style={{ marginTop: 14 }}>
              <input
                className="tf-input"
                style={{ maxWidth: 200 }}
                placeholder="Staging"
                value={envName}
                onChange={(event) => setEnvName(event.target.value)}
              />
              <Button
                onClick={() => createEnvironment.mutate()}
                disabled={createEnvironment.isPending || !envName.trim()}
              >
                Add environment
              </Button>
            </div>
          ) : null}
        </Card>
      </div>

      <div className="tf-grid" style={{ gridTemplateColumns: "1fr 1fr", marginTop: 16 }}>
        <Card>
          <h2 style={{ margin: 0, fontSize: 18 }}>Usage</h2>
          {usage.data ? (
            <>
              <div className="tf-kpi" style={{ marginTop: 12 }}>{usage.data.used.toLocaleString()}</div>
              <div className="tf-muted">of {usage.data.limit.toLocaleString()} actions this plan</div>
              <div style={{ height: 8, background: "var(--tf-surface-2)", borderRadius: 999, marginTop: 14, overflow: "hidden" }}>
                <div
                  style={{
                    height: "100%",
                    width: `${Math.min(100, Math.round((usage.data.used / usage.data.limit) * 100))}%`,
                    background: "var(--tf-accent)",
                  }}
                />
              </div>
            </>
          ) : (
            <p className="tf-muted">No usage yet.</p>
          )}
        </Card>

        <Card>
          <h2 style={{ margin: 0, fontSize: 18 }}>Audit log</h2>
          {audit.data?.items.length ? (
            <div className="tf-list" style={{ marginTop: 10 }}>
              {audit.data.items.slice(0, 8).map((event) => (
                <div className="tf-list-row" key={event.id}>
                  <div>
                    <div className="tf-mono">{event.action}</div>
                    <div className="tf-muted">{event.actor_type} · {event.target ?? "—"}</div>
                  </div>
                  <span className="tf-muted">{formatDate(event.created_at)}</span>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState title="No audit events yet" />
          )}
        </Card>
      </div>

      <Card style={{ marginTop: 16 }}>
        <div className="tf-actions" style={{ justifyContent: "space-between" }}>
          <h2 style={{ margin: 0, fontSize: 18 }}>Billing</h2>
          <Badge tone={billing.data?.stripeConfigured ? "ok" : "muted"}>
            {billing.data?.stripeConfigured ? "Stripe connected" : "not configured"}
          </Badge>
        </div>
        {billing.data ? (
          <>
            <p className="tf-muted">
              Plan <strong>{billing.data.plan}</strong> · status{" "}
              <strong>{billing.data.status}</strong>
              {billing.data.currentPeriodEnd
                ? ` · renews ${formatDate(billing.data.currentPeriodEnd)}`
                : ""}
            </p>
            <div style={{ height: 8, background: "var(--tf-surface-2)", borderRadius: 999, overflow: "hidden" }}>
              <div
                style={{
                  height: "100%",
                  width: `${Math.min(100, Math.round((billing.data.usage.used / billing.data.usage.limit) * 100))}%`,
                  background: "var(--tf-accent)",
                }}
              />
            </div>
            <p className="tf-muted">
              {billing.data.usage.used.toLocaleString()} of{" "}
              {billing.data.usage.limit.toLocaleString()} actions this month
            </p>
            <div className="tf-actions">
              <Button
                variant="primary"
                onClick={() => checkout.mutate("team")}
                disabled={!billing.data.stripeConfigured || checkout.isPending}
              >
                Upgrade to Team
              </Button>
              <Button
                onClick={() => checkout.mutate("growth")}
                disabled={!billing.data.stripeConfigured || checkout.isPending}
              >
                Upgrade to Growth
              </Button>
              {billing.data.customerId ? (
                <Button onClick={() => portal.mutate()} disabled={portal.isPending}>
                  Manage billing
                </Button>
              ) : null}
            </div>
            {!billing.data.stripeConfigured ? (
              <p className="tf-muted">
                Stripe billing is not configured for this deployment. Usage and plan limits are
                still enforced.
              </p>
            ) : null}
          </>
        ) : (
          <p className="tf-muted">Loading billing…</p>
        )}
      </Card>

      <Card style={{ marginTop: 16 }}>
        <div className="tf-actions" style={{ justifyContent: "space-between" }}>
          <h2 style={{ margin: 0, fontSize: 18 }}>Webhooks</h2>
          <Badge tone="muted">signed deliveries</Badge>
        </div>
        <p className="tf-muted">
          Receive signed event deliveries for actions, evidence packs, verification links, keys,
          environments, and policies. Verify the `x-tessera-signature` header with your endpoint
          secret.
        </p>
        <div className="tf-actions">
          <input
            className="tf-input"
            style={{ maxWidth: 380 }}
            placeholder="https://example.com/tessera/webhook"
            value={webhookUrl}
            onChange={(event) => setWebhookUrl(event.target.value)}
          />
          <Button
            variant="primary"
            onClick={() => createWebhook.mutate()}
            disabled={createWebhook.isPending || !webhookUrl.trim()}
          >
            {createWebhook.isPending ? "Adding…" : "Add webhook"}
          </Button>
        </div>
        {webhookSecret ? (
          <p className="tf-muted" style={{ marginTop: 10 }}>
            Signing secret (shown once): <span className="tf-mono">{webhookSecret}</span>
          </p>
        ) : null}
        <div className="tf-list" style={{ marginTop: 14 }}>
          {webhooks.data?.items.map((webhook) => (
            <div className="tf-list-row" key={webhook.id}>
              <div>
                <div className="tf-mono">{webhook.url}</div>
                <div className="tf-muted">{webhook.events.join(", ") || "all events"}</div>
              </div>
              <div className="tf-actions">
                <Badge tone={webhook.active ? "ok" : "muted"}>{webhook.active ? "active" : "disabled"}</Badge>
                <Button variant="danger" onClick={() => removeWebhook.mutate(webhook.id)}>Remove</Button>
              </div>
            </div>
          ))}
          {!webhooks.data?.items.length ? <p className="tf-muted">No webhooks yet.</p> : null}
        </div>
        {deliveries.data?.items.length ? (
          <>
            <h3 style={{ marginTop: 18, fontSize: 14 }}>Recent deliveries</h3>
            <div className="tf-list">
              {deliveries.data.items.slice(0, 8).map((delivery) => (
                <div className="tf-list-row" key={delivery.id}>
                  <div>
                    <div className="tf-mono">{delivery.event}</div>
                    <div className="tf-muted">
                      attempts {delivery.attempts} · {formatDate(delivery.created_at)}
                    </div>
                  </div>
                  <Badge tone={delivery.status === "delivered" ? "ok" : delivery.status === "failed" ? "bad" : "warn"}>
                    {delivery.status}
                  </Badge>
                </div>
              ))}
            </div>
          </>
        ) : null}
      </Card>
    </>
  );
}
