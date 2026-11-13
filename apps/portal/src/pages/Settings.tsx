import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, type Usage } from "../api";
import { useWorkspace } from "../App";
import {
  Badge,
  Button,
  Card,
  CopyRow,
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
  const [confirmDelete, setConfirmDelete] = useState("");
  const [retentionDays, setRetentionDays] = useState(String(me.org.retention_days ?? 365));
  const [scimToken, setScimToken] = useState<string | null>(null);

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
  const scimTokens = useQuery({
    queryKey: ["scim-tokens"],
    queryFn: () => api<{ items: Array<{ id: string; name: string; created_at: string; last_used_at: string | null; expires_at: string | null; revoked_at: string | null }> }>("/v1/scim-tokens"),
    enabled: me.role === "owner" || me.role === "admin",
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

  const createScimToken = useMutation({
    mutationFn: () =>
      api<{ token: string }>("/v1/scim-tokens", {
        method: "POST",
        body: JSON.stringify({ name: "Identity provider" }),
      }),
    onSuccess: async (data) => {
      setScimToken(data.token);
      setError(null);
      await queryClient.invalidateQueries({ queryKey: ["scim-tokens"] });
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  const revokeScimToken = useMutation({
    mutationFn: (id: string) => api(`/v1/scim-tokens/${id}`, { method: "DELETE" }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["scim-tokens"] });
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  const requestDeletion = useMutation({
    mutationFn: () =>
      api<{ purgeAfter: string }>("/v1/org/deletion-request", {
        method: "POST",
        body: JSON.stringify({ confirm: confirmDelete }),
      }),
    onSuccess: async () => {
      setConfirmDelete("");
      setError(null);
      refresh();
      await queryClient.invalidateQueries();
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  const cancelDeletion = useMutation({
    mutationFn: () => api("/v1/org/deletion-cancel", { method: "POST", body: "{}" }),
    onSuccess: async () => {
      setError(null);
      refresh();
      await queryClient.invalidateQueries();
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  const saveRetention = useMutation({
    mutationFn: () =>
      api("/v1/org/retention", {
        method: "PATCH",
        body: JSON.stringify({ retentionDays: Number(retentionDays) }),
      }),
    onSuccess: async () => {
      setError(null);
      await queryClient.invalidateQueries();
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
            {billing.data.stripeConfigured ? (
              <div className="tf-actions">
                <Button
                  variant="primary"
                  onClick={() => checkout.mutate("team")}
                  disabled={checkout.isPending}
                >
                  Upgrade to Team
                </Button>
                <Button
                  onClick={() => checkout.mutate("growth")}
                  disabled={checkout.isPending}
                >
                  Upgrade to Growth
                </Button>
                {billing.data.customerId ? (
                  <Button onClick={() => portal.mutate()} disabled={portal.isPending}>
                    Manage billing
                  </Button>
                ) : null}
              </div>
            ) : (
              <p className="tf-muted">
                Tessera is in design-partner mode. Billing is disabled until the pilot program
                converts; usage limits still apply.
              </p>
            )}
          </>
        ) : (
          <p className="tf-muted">Loading billing…</p>
        )}
      </Card>

      {me.role === "owner" || me.role === "admin" ? (
      <Card style={{ marginTop: 16 }}>
        <div className="tf-actions" style={{ justifyContent: "space-between" }}>
          <h2 style={{ margin: 0, fontSize: 18 }}>Data controls</h2>
          <Badge tone="muted">owner/admin</Badge>
        </div>
        <p className="tf-muted">
          Export tenant metadata and the action read model as JSON. Broker receipts remain in the
          broker tenant and are available through evidence packs.
        </p>
        <div className="tf-actions">
          <Button onClick={() => window.location.assign("/v1/org/export")}>Export data</Button>
          <input
            className="tf-input"
            style={{ maxWidth: 160 }}
            type="number"
            min={30}
            max={3650}
            value={retentionDays}
            onChange={(event) => setRetentionDays(event.target.value)}
            aria-label="Retention days"
          />
          <Button
            onClick={() => saveRetention.mutate()}
            disabled={saveRetention.isPending || Number(retentionDays) < 30}
          >
            Save retention
          </Button>
        </div>
        {me.role === "owner" ? (
          <div style={{ marginTop: 18, borderTop: "1px solid var(--tf-border)", paddingTop: 14 }}>
            {me.org.deletion_scheduled_for ? (
              <>
                <p className="tf-muted">
                  Deletion requested. Purge date: <strong>{formatDate(me.org.deletion_scheduled_for)}</strong>.
                  Export anything you need before then.
                </p>
                <Button variant="danger" onClick={() => cancelDeletion.mutate()} disabled={cancelDeletion.isPending}>
                  Cancel deletion
                </Button>
              </>
            ) : (
              <>
                <p className="tf-muted">
                  Request workspace deletion. This records a 30-day grace period; it does not delete
                  broker receipts or evidence automatically. Operator purge follows the documented
                  data-lifecycle runbook.
                </p>
                <div className="tf-actions">
                  <input
                    className="tf-input"
                    style={{ maxWidth: 220 }}
                    placeholder={`Type "${me.org.name}"`}
                    value={confirmDelete}
                    onChange={(event) => setConfirmDelete(event.target.value)}
                  />
                  <Button
                    variant="danger"
                    onClick={() => requestDeletion.mutate()}
                    disabled={requestDeletion.isPending || confirmDelete !== me.org.name}
                  >
                    Request deletion
                  </Button>
                </div>
              </>
            )}
          </div>
        ) : null}
      </Card>

      ) : null}
      {me.role === "owner" || me.role === "admin" ? (
        <Card style={{ marginTop: 16 }}>
          <div className="tf-actions" style={{ justifyContent: "space-between" }}>
            <h2 style={{ margin: 0, fontSize: 18 }}>SCIM provisioning</h2>
            <Badge tone="muted">Users</Badge>
          </div>
          <p className="tf-muted">
            Create an organization-scoped token for your identity provider. Tokens are shown once
            and can provision users and admins in this workspace.
          </p>
          <div className="tf-actions">
            <Button variant="primary" onClick={() => createScimToken.mutate()} disabled={createScimToken.isPending}>
              {createScimToken.isPending ? "Creating…" : "Create SCIM token"}
            </Button>
          </div>
          {scimToken ? (
            <div style={{ marginTop: 12 }}>
              <p className="tf-muted">Store this token in your IdP now; it will not be shown again.</p>
              <CopyRow value={scimToken} />
            </div>
          ) : null}
          <div className="tf-list" style={{ marginTop: 12 }}>
            {scimTokens.data?.items.filter((token) => !token.revoked_at).map((token) => (
              <div className="tf-list-row" key={token.id}>
                <div>
                  <div>{token.name}</div>
                  <div className="tf-muted">
                    created {formatDate(token.created_at)}
                    {token.last_used_at ? ` · last used ${formatDate(token.last_used_at)}` : ""}
                    {token.expires_at ? ` · expires ${formatDate(token.expires_at)}` : ""}
                  </div>
                </div>
                <Button variant="danger" onClick={() => revokeScimToken.mutate(token.id)} disabled={revokeScimToken.isPending}>
                  Revoke
                </Button>
              </div>
            ))}
            {!scimTokens.data?.items.filter((token) => !token.revoked_at).length ? (
              <p className="tf-muted">No active SCIM tokens.</p>
            ) : null}
          </div>
        </Card>
      ) : null}

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
