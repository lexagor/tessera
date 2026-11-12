import { useMemo, useState, type CSSProperties } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";

import { api } from "../api";
import { useWorkspace } from "../App";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorBanner,
  ErrorState,
  Modal,
  PageHeader,
  Skeleton,
  formatDate,
} from "@tessera/ui";
import {
  authModeLabel,
  integrationStatusLabel,
  integrationStatusTone,
  providerMark,
  riskTone,
  type IntegrationConnection,
  type IntegrationCredentialField,
  type IntegrationProvider,
  type IntegrationScope,
  type IntegrationsResponse,
  type ProbeResult,
} from "../lib/integrations";

type Filter = "all" | "connected" | "attention" | "available";

const FILTERS: Array<{ id: Filter; label: string }> = [
  { id: "all", label: "All providers" },
  { id: "connected", label: "Connected" },
  { id: "attention", label: "Needs attention" },
  { id: "available", label: "Available" },
];

interface SetupState {
  provider: IntegrationProvider;
  step: 1 | 2 | 3;
  name: string;
  scopes: string[];
  credential: Record<string, string>;
  result: {
    integration: IntegrationConnection;
    warning?: string;
  } | null;
}

interface RotateState {
  connection: IntegrationConnection;
  provider: IntegrationProvider;
  credential: Record<string, string>;
}

export function IntegrationsPage() {
  const { environmentId, me } = useWorkspace();
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const initialFilter = searchParams.get("filter");
  const [filter, setFilter] = useState<Filter>(
    initialFilter === "connected" || initialFilter === "attention" || initialFilter === "available"
      ? initialFilter
      : "all",
  );
  const [setup, setSetup] = useState<SetupState | null>(null);
  const [rotate, setRotate] = useState<RotateState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<{ tone: "ok" | "warn"; message: string } | null>(null);
  const [testingId, setTestingId] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ["integrations", environmentId],
    queryFn: () => api<IntegrationsResponse>(`/v1/integrations?environmentId=${encodeURIComponent(environmentId)}`),
    enabled: Boolean(environmentId),
  });

  const providers = query.data?.providers ?? [];
  const items = query.data?.items ?? [];
  const canWrite = me.role === "owner" || me.role === "admin" || me.role === "member";
  const canRotate = me.role === "owner" || me.role === "admin";
  const byProvider = useMemo(
    () => new Map(items.map((item) => [item.provider, item])),
    [items],
  );

  const connected = items.filter((item) => item.status === "connected").length;
  const attention = items.filter((item) => item.status === "needs_attention").length;
  const scopes = items.reduce((sum, item) => sum + item.scopes.length, 0);
  const lastSync = items
    .map((item) => item.lastSyncAt)
    .filter((value): value is string => Boolean(value))
    .sort()
    .at(-1);
  const filtered = providers.filter((provider) => {
    const connection = byProvider.get(provider.id);
    if (filter === "connected") return connection?.status === "connected";
    if (filter === "attention") return connection?.status === "needs_attention";
    if (filter === "available") return !connection;
    return true;
  });

  const testConnection = useMutation({
    mutationFn: (connection: IntegrationConnection) =>
      api<{ integration: IntegrationConnection; probe: ProbeResult }>(
        `/v1/integrations/${connection.id}/test?environmentId=${encodeURIComponent(environmentId)}`,
        { method: "POST" },
      ),
    onMutate: (connection) => {
      setTestingId(connection.id);
      setError(null);
    },
    onSuccess: async (result) => {
      setNotice({
        tone: result.probe.ok ? "ok" : "warn",
        message: result.probe.message,
      });
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["integrations"] }),
        queryClient.invalidateQueries({ queryKey: ["actions"] }),
      ]);
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
    onSettled: () => setTestingId(null),
  });

  const rotateCredential = useMutation({
    mutationFn: ({ connection, credential }: { connection: IntegrationConnection; credential: Record<string, string> }) =>
      api<IntegrationConnection>(
        `/v1/integrations/${connection.id}/rotate?environmentId=${encodeURIComponent(environmentId)}`,
        { method: "POST", body: JSON.stringify({ credential }) },
      ),
    onSuccess: async () => {
      setRotate(null);
      setNotice({ tone: "warn", message: "Credential rotated. Run Test connection to verify it." });
      await queryClient.invalidateQueries({ queryKey: ["integrations"] });
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  const createIntegration = useMutation({
    mutationFn: (state: SetupState) =>
      api<{ integration: IntegrationConnection; warning?: string }>(
        `/v1/integrations?environmentId=${encodeURIComponent(environmentId)}`,
        {
          method: "POST",
          body: JSON.stringify({
            provider: state.provider.id,
            name: state.name,
            scopes: state.scopes,
            credential: state.credential,
          }),
        },
      ),
    onSuccess: async (result) => {
      setError(null);
      setSetup((current) => (current ? { ...current, step: 3, result } : current));
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["integrations"] }),
        queryClient.invalidateQueries({ queryKey: ["actions"] }),
        queryClient.invalidateQueries({ queryKey: ["policies"] }),
        queryClient.invalidateQueries({ queryKey: ["usage"] }),
      ]);
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  function chooseFilter(next: Filter) {
    setFilter(next);
    const params = new URLSearchParams(searchParams);
    if (next === "all") params.delete("filter");
    else params.set("filter", next);
    setSearchParams(params, { replace: true });
  }

  function openSetup(provider: IntegrationProvider) {
    setError(null);
    setNotice(null);
    setSetup({
      provider,
      step: 1,
      name: provider.name,
      scopes: provider.scopes.map((scope) => scope.id),
      credential: {},
      result: null,
    });
  }

  function closeSetup() {
    setSetup(null);
    setError(null);
  }

  function openRotate(connection: IntegrationConnection, provider: IntegrationProvider) {
    setError(null);
    setNotice(null);
    setRotate({ connection, provider, credential: {} });
  }

  if (query.isLoading) {
    return (
      <>
        <PageHeader title="Integrations" subtitle="Loading provider coverage and credential posture…" />
        <div className="tf-integration-grid">
          {Array.from({ length: 4 }).map((_, index) => (
            <Card key={index}>
              <Skeleton width="46%" height={16} />
              <Skeleton width="82%" height={10} style={{ marginTop: 12 }} />
              <Skeleton width="100%" height={52} style={{ marginTop: 16 }} />
              <Skeleton width="64%" height={10} style={{ marginTop: 12 }} />
            </Card>
          ))}
        </div>
      </>
    );
  }

  if (query.isError) {
    return (
      <>
        <PageHeader title="Integrations" subtitle="Provider coverage and credential posture." />
        <ErrorState
          title="Integrations are unavailable"
          message={query.error instanceof Error ? query.error.message : "Could not load integration coverage."}
          action={<Button onClick={() => query.refetch()}>Retry</Button>}
        />
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Integrations"
        subtitle="Make coverage visible: every provider, its scopes, its owner, and the last time Tessera proved the path."
        actions={
          canWrite ? (
            <Button variant="primary" onClick={() => items.length < providers.length && openSetup(nextAvailable(providers, byProvider)!)} disabled={!providers.length || items.length >= providers.length}>
              Add integration
            </Button>
          ) : undefined
        }
      />
      <ErrorBanner message={error} />
      {notice ? (
        <div className={`tf-notice ${notice.tone}`}>
          <span>{notice.message}</span>
          <button onClick={() => setNotice(null)} aria-label="Dismiss">×</button>
        </div>
      ) : null}

      <div className="tf-stat-row">
        <Card>
          <div className="tf-kpi-label">Provider coverage</div>
          <div className="tf-stat-value">{connected}<span className="tf-stat-denom">/{providers.length || 8}</span></div>
          <div className="tf-muted">{attention ? `${attention} need attention` : "All connected providers healthy"}</div>
        </Card>
        <Card>
          <div className="tf-kpi-label">Permission scopes</div>
          <div className="tf-stat-value">{scopes}</div>
          <div className="tf-muted">authorized surface areas</div>
        </Card>
        <Card>
          <div className="tf-kpi-label">Needs attention</div>
          <div className={`tf-stat-value ${attention ? "tf-text-warning" : ""}`}>{attention}</div>
          <div className="tf-muted">missing credentials or failed tests</div>
        </Card>
        <Card>
          <div className="tf-kpi-label">Last sync</div>
          <div className="tf-stat-value tf-stat-value-small">{lastSync ? formatDate(lastSync) : "—"}</div>
          <div className="tf-muted">last provider check</div>
        </Card>
      </div>

      <Card className="tf-coverage-card">
        <div className="tf-coverage-head">
          <div>
            <div className="tf-kpi-label">Coverage map</div>
            <h2>Systems in front of the control plane</h2>
          </div>
          <span className="tf-muted">{connected} connected · {items.length} configured · {providers.length} available</span>
        </div>
        <div className="tf-coverage-bar" aria-label="Provider connection coverage">
          {providers.map((provider) => {
            const connection = byProvider.get(provider.id);
            return (
              <span
                key={provider.id}
                className={`tf-coverage-segment ${connection?.status ?? "available"}`}
                title={`${provider.name}: ${connection ? integrationStatusLabel(connection.status) : "Available"}`}
              />
            );
          })}
        </div>
        <div className="tf-coverage-legend">
          <span><i className="connected" />Connected</span>
          <span><i className="needs_attention" />Needs attention</span>
          <span><i className="available" />Available</span>
        </div>
      </Card>

      <div className="tf-integration-toolbar">
        <div className="tf-saved-views" role="tablist" aria-label="Integration filters">
          {FILTERS.map((item) => (
            <button
              key={item.id}
              className={`tf-saved-view ${filter === item.id ? "active" : ""}`}
              onClick={() => chooseFilter(item.id)}
              role="tab"
              aria-selected={filter === item.id}
            >
              {item.label}
            </button>
          ))}
        </div>
        <span className="tf-muted">{filtered.length} provider{filtered.length === 1 ? "" : "s"}</span>
      </div>

      {filtered.length ? (
        <div className="tf-integration-grid">
          {filtered.map((provider) => {
            const connection = byProvider.get(provider.id);
            return (
              <Card className="tf-integration-card" key={provider.id}>
                <div className="tf-integration-head">
                  <span
                    className="tf-integration-mark"
                    style={{
                      "--tf-provider": provider.color,
                      background: `color-mix(in srgb, ${provider.color} 14%, transparent)`,
                      color: provider.color,
                    } as CSSProperties}
                  >
                    {providerMark(provider.id)}
                  </span>
                  <div className="tf-integration-title">
                    <div className="tf-integration-name">
                      <h2>{provider.name}</h2>
                      <MaturityBadge maturity={provider.maturity} />
                    </div>
                    <span className="tf-muted">{provider.category}</span>
                  </div>
                  <Badge tone={connection ? integrationStatusTone(connection.status) : "muted"}>
                    {connection ? integrationStatusLabel(connection.status) : "Available"}
                  </Badge>
                </div>
                <p className="tf-integration-description">{provider.description}</p>

                {connection ? (
                  <>
                    <div className="tf-integration-meta">
                      <div><span>Environment</span><strong>{connection.environment.name}</strong></div>
                      <div><span>Owner</span><strong>{connection.owner?.email ?? "Unassigned"}</strong></div>
                      <div><span>Last sync</span><strong>{formatDate(connection.lastSyncAt)}</strong></div>
                      <div><span>Credential</span><strong>{credentialLabel(connection)}</strong></div>
                    </div>
                    <div className="tf-scope-list">
                      {connection.scopes.map((scope) => (
                        <span className="tf-scope-chip" key={scope.id}>
                          <span>{scope.label}</span>
                          <Badge tone={riskTone(scope.risk)}>{scope.risk}</Badge>
                        </span>
                      ))}
                    </div>
                    {connection.lastTestMessage ? (
                      <div className={`tf-integration-test-note ${connection.lastTestOk ? "ok" : "warn"}`}>
                        {connection.lastTestMessage}
                      </div>
                    ) : null}
                    <div className="tf-integration-actions">
                      {canWrite ? (
                        <Button
                          variant="primary"
                          onClick={() => testConnection.mutate(connection)}
                          disabled={testingId === connection.id}
                        >
                          {testingId === connection.id ? "Testing…" : "Test connection"}
                        </Button>
                      ) : null}
                      {canRotate && provider.credentialFields.length ? (
                        <Button variant="ghost" onClick={() => openRotate(connection, provider)}>
                          Rotate credential
                        </Button>
                      ) : null}
                      {connection.policyId ? <Link className="tf-btn ghost" to={`/policies?policy=${encodeURIComponent(connection.policyId)}`}>View policy</Link> : null}
                      {connection.testActionId ? <Link className="tf-btn ghost" to={`/actions/${connection.testActionId}`}>Test action</Link> : null}
                    </div>
                  </>
                ) : (
                  <>
                    <div className="tf-scope-preview">
                      {provider.scopes.slice(0, 3).map((scope) => (
                        <span className="tf-scope-chip" key={scope.id}>
                          <span>{scope.label}</span>
                          <Badge tone={riskTone(scope.risk)}>{scope.risk}</Badge>
                        </span>
                      ))}
                    </div>
                    <div className="tf-integration-actions">
                      {canWrite ? <Button variant="primary" onClick={() => openSetup(provider)}>Set up</Button> : null}
                      <span className="tf-muted">{provider.authMode === "broker_managed" ? "Broker holds the credential" : authModeLabel(provider.authMode)}</span>
                    </div>
                  </>
                )}
              </Card>
            );
          })}
        </div>
      ) : (
        <Card>
          <EmptyState title="No providers in this view">
            Try another filter or add an integration to expand coverage.
          </EmptyState>
        </Card>
      )}

      {setup ? (
        <SetupModal
          state={setup}
          environment={me.environments.find((environment) => environment.id === environmentId)}
          owner={me.user.email}
          error={error}
          pending={createIntegration.isPending}
          onChange={setSetup}
          onClose={closeSetup}
          onSubmit={() => createIntegration.mutate(setup)}
        />
      ) : null}

      {rotate ? (
        <RotateModal
          state={rotate}
          error={error}
          pending={rotateCredential.isPending}
          onChange={setRotate}
          onClose={() => setRotate(null)}
          onSubmit={() => rotateCredential.mutate({ connection: rotate.connection, credential: rotate.credential })}
        />
      ) : null}
    </>
  );
}

function credentialLabel(connection: IntegrationConnection): string {
  if (connection.hasCredential) return `Encrypted ${connection.credentialHint ?? ""}`.trim();
  if (connection.authMode === "broker_managed") return "Broker-managed";
  if (connection.authMode === "sdk") return "SDK";
  return `Missing · ${authModeLabel(connection.authMode)}`;
}

function nextAvailable(
  providers: IntegrationProvider[],
  byProvider: Map<string, IntegrationConnection>,
): IntegrationProvider | undefined {
  return providers.find((provider) => !byProvider.get(provider.id));
}

function MaturityBadge({ maturity }: { maturity: IntegrationProvider["maturity"] }) {
  return (
    <Badge tone={maturity === "ga" ? "ok" : maturity === "sdk" ? "muted" : "warn"}>
      {maturity === "ga" ? "GA" : maturity === "sdk" ? "SDK" : "Preview"}
    </Badge>
  );
}

function SetupModal({
  state,
  environment,
  owner,
  error,
  pending,
  onChange,
  onClose,
  onSubmit,
}: {
  state: SetupState;
  environment?: { name: string };
  owner: string;
  error: string | null;
  pending: boolean;
  onChange: (state: SetupState) => void;
  onClose: () => void;
  onSubmit: () => void;
}) {
  const { provider } = state;
  const selectedScopes = provider.scopes.filter((scope) => state.scopes.includes(scope.id));

  function toggleScope(id: string) {
    onChange({
      ...state,
      scopes: state.scopes.includes(id)
        ? state.scopes.filter((scope) => scope !== id)
        : [...state.scopes, id],
    });
  }

  function setCredential(key: string, value: string) {
    onChange({ ...state, credential: { ...state.credential, [key]: value } });
  }

  if (state.result) {
    return (
      <Modal title={`${provider.name} ${state.result.integration.status === "connected" ? "connected" : "set up"}`} onClose={onClose} wide>
        <div className="tf-setup-result">
          <div className="tf-setup-result-mark">{providerMark(provider.id)}</div>
          <div>
            <h3>{state.result.integration.status === "connected" ? "Coverage is live" : "Connection created; credential needed"}</h3>
            <p className="tf-muted">{state.result.integration.lastTestMessage}</p>
            {state.result.warning ? <div className="tf-notice warn">{state.result.warning}</div> : null}
          </div>
        </div>
        <div className="tf-proof-rows" style={{ marginTop: 16 }}>
          <ResultRow label="Policy" value={state.result.integration.policyId ?? "—"} />
          <ResultRow label="Test action" value={state.result.integration.testActionId ?? "—"} />
          <ResultRow label="Scopes" value={`${state.result.integration.scopes.length} authorized`} />
          <ResultRow label="Credential" value={state.result.integration.hasCredential ? "encrypted at rest" : authModeLabel(state.result.integration.authMode)} />
        </div>
        <div className="tf-modal-actions">
          {state.result.integration.testActionId ? (
            <Link className="tf-btn" to={`/actions/${state.result.integration.testActionId}`}>View test action</Link>
          ) : null}
          <Button variant="primary" onClick={onClose}>Done</Button>
        </div>
      </Modal>
    );
  }

  return (
    <Modal title={`Set up ${provider.name}`} onClose={onClose} wide>
      <div className="tf-setup-steps">
        {[1, 2, 3].map((step) => <span key={step} className={state.step >= step ? "active" : ""}>{step}</span>)}
        <small>{state.step === 1 ? "Scope" : state.step === 2 ? "Credential" : "Review"}</small>
      </div>
      <ErrorBanner message={error} />

      {state.step === 1 ? (
        <>
          <p>Choose the permissions this connection may exercise. Tessera creates a least-privilege baseline policy from this selection.</p>
          <div className="tf-form-grid">
            <label className="tf-field">Connection name
              <input className="tf-input" value={state.name} onChange={(event) => onChange({ ...state, name: event.target.value })} />
            </label>
            <label className="tf-field">Environment
              <input className="tf-input" value={environment?.name ?? "Environment"} readOnly />
            </label>
          </div>
          <div className="tf-field" style={{ marginTop: 14 }}>Permission scope</div>
          <div className="tf-scope-picker">
            {provider.scopes.map((scope) => (
              <label key={scope.id} className={`tf-scope-option ${state.scopes.includes(scope.id) ? "selected" : ""}`}>
                <input type="checkbox" checked={state.scopes.includes(scope.id)} onChange={() => toggleScope(scope.id)} />
                <span>
                  <strong>{scope.label}</strong>
                  <small>{scope.description}</small>
                  <code>{scope.resource}</code>
                </span>
                <Badge tone={riskTone(scope.risk)}>{scope.risk}</Badge>
              </label>
            ))}
          </div>
          <div className="tf-setup-owner">Owner <strong>{owner}</strong> · Policy and test action will be created on submit.</div>
          <div className="tf-modal-actions">
            <Button variant="ghost" onClick={onClose}>Cancel</Button>
            <Button variant="primary" onClick={() => onChange({ ...state, step: 2 })} disabled={!state.name.trim() || !state.scopes.length}>
              Continue
            </Button>
          </div>
        </>
      ) : state.step === 2 ? (
        <>
          <p>
            {provider.authMode === "broker_managed"
              ? "The broker can manage this provider without a pasted secret. Add an optional credential to run a live connection test."
              : provider.authMode === "sdk"
                ? "This integration uses the published SDK. No provider credential is required."
                : "Credentials are encrypted with the control-plane key and never returned by the API. You can skip this for now and add it later."}
          </p>
          {provider.credentialFields.length ? (
            <div className="tf-form-grid">
              {provider.credentialFields.map((field) => (
                <CredentialField
                  key={field.key}
                  field={field}
                  value={state.credential[field.key] ?? ""}
                  onChange={(value) => setCredential(field.key, value)}
                />
              ))}
            </div>
          ) : (
            <div className="tf-notice ok">No credential needed for this SDK integration.</div>
          )}
          <div className="tf-modal-actions">
            <Button variant="ghost" onClick={() => onChange({ ...state, step: 1 })}>Back</Button>
            <Button variant="primary" onClick={() => onChange({ ...state, step: 3 })}>Review</Button>
          </div>
        </>
      ) : (
        <>
          <p>Review the first policy and test action before creating this connection.</p>
          <div className="tf-proof-rows">
            <ResultRow label="Provider" value={provider.name} />
            <ResultRow label="Environment" value={environment?.name ?? "Environment"} />
            <ResultRow label="Owner" value={owner} />
            <ResultRow label="Policy" value={`${selectedScopes.length} allow rule${selectedScopes.length === 1 ? "" : "s"}`} />
            <ResultRow label="Test action" value={selectedScopes[0]?.resource ?? provider.sample.tool} />
            <ResultRow label="Credential" value={Object.keys(state.credential).length ? "encrypted at rest" : authModeLabel(provider.authMode)} />
          </div>
          <div className="tf-scope-review">
            {selectedScopes.map((scope) => <code key={scope.id}>{scope.resource}</code>)}
          </div>
          <ErrorBanner message={error} />
          <div className="tf-modal-actions">
            <Button variant="ghost" onClick={() => onChange({ ...state, step: 2 })}>Back</Button>
            <Button variant="primary" onClick={onSubmit} disabled={pending}>
              {pending ? "Creating policy & test action…" : "Connect & run test action"}
            </Button>
          </div>
        </>
      )}
    </Modal>
  );
}

function RotateModal({
  state,
  error,
  pending,
  onChange,
  onClose,
  onSubmit,
}: {
  state: RotateState;
  error: string | null;
  pending: boolean;
  onChange: (state: RotateState) => void;
  onClose: () => void;
  onSubmit: () => void;
}) {
  return (
    <Modal title={`Rotate ${state.provider.name} credential`} onClose={onClose} wide>
      <p>The new credential is encrypted at rest. The connection moves to needs attention until it passes a test.</p>
      <ErrorBanner message={error} />
      <div className="tf-form-grid">
        {state.provider.credentialFields.map((field) => (
          <CredentialField
            key={field.key}
            field={field}
            value={state.credential[field.key] ?? ""}
            onChange={(value) =>
              onChange({ ...state, credential: { ...state.credential, [field.key]: value } })
            }
          />
        ))}
      </div>
      <div className="tf-modal-actions">
        <Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button variant="primary" onClick={onSubmit} disabled={pending || !Object.keys(state.credential).length}>
          {pending ? "Rotating…" : "Rotate credential"}
        </Button>
      </div>
    </Modal>
  );
}

function CredentialField({
  field,
  value,
  onChange,
}: {
  field: IntegrationCredentialField;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <label className="tf-field">
      {field.label}{field.required ? "" : " (optional)"}
      <input
        className="tf-input"
        type={field.secret ? "password" : "text"}
        placeholder={field.placeholder}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        autoComplete="off"
      />
      {field.help ? <small className="tf-muted">{field.help}</small> : null}
    </label>
  );
}

function ResultRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="tf-proof-row">
      <span>{label}</span>
      <strong className="tf-mono" style={{ fontSize: 11, textAlign: "right" }}>{value}</strong>
    </div>
  );
}
