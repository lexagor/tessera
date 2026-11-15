import { useEffect, useMemo, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { api, environmentQuery, type VerificationLink } from "../api";
import { useWorkspace } from "../App";
import {
  Badge,
  Button,
  Card,
  CopyRow,
  ErrorBanner,
  PageHeader,
} from "@tessera/ui";

interface PolicyTemplate {
  id: string;
  name: string;
  description: string;
  resource: string;
  grants: Array<Record<string, unknown>>;
  example: {
    tool: string;
    args: Record<string, unknown>;
  };
  test: {
    tool: string;
    args: Record<string, unknown>;
    riskClass: string;
  };
}

const TEMPLATES: PolicyTemplate[] = [
  {
    id: "quickstart-refunds",
    name: "Refund cap",
    description: "Allow Stripe refunds up to $5, then deny a $42 test request.",
    resource: "stripe:refunds.create",
    grants: [
      {
        resource: "stripe:refunds.create",
        constraints: [{ type: "max_number", field: "amount", value: 500 }],
      },
    ],
    example: {
      tool: "stripe.refunds.create",
      args: { amount: 100, currency: "usd", payment_intent: "pi_your_test_payment" },
    },
    test: {
      tool: "stripe.refunds.create",
      args: { charge: "ch_quickstart", amount: 4200, reason: "quickstart policy check" },
      riskClass: "high",
    },
  },
  {
    id: "quickstart-github-issues",
    name: "GitHub issues only",
    description: "Allow issue creation, then deny a pull-request test.",
    resource: "github:issues.create",
    grants: [{ resource: "github:issues.create" }],
    example: {
      tool: "github.issues.create",
      args: { repo: "acme/platform", title: "Investigate checkout latency" },
    },
    test: {
      tool: "github.pulls.create",
      args: { repo: "acme/platform", title: "quickstart policy check" },
      riskClass: "high",
    },
  },
  {
    id: "quickstart-slack-posts",
    name: "Slack posts",
    description: "Allow chat posts, then deny a file-delete test.",
    resource: "slack:chat.postMessage",
    grants: [{ resource: "slack:chat.postMessage" }],
    example: {
      tool: "slack.chat.postMessage",
      args: { channel: "#support", text: "Tessera quickstart" },
    },
    test: {
      tool: "slack.files.delete",
      args: { file: "F_quickstart" },
      riskClass: "high",
    },
  },
];

interface AuthorizeResult {
  actionId: string;
  decision: "allow" | "deny";
  receiptId: string;
}

export function QuickstartPage() {
  const { me, environmentId, setEnvironmentId, refresh } = useWorkspace();
  const queryClient = useQueryClient();
  const [environmentName, setEnvironmentName] = useState("Production");
  const [templateId, setTemplateId] = useState(TEMPLATES[0]!.id);
  const [policySaved, setPolicySaved] = useState(false);
  const [agentKey, setAgentKey] = useState<string | null>(null);
  const [result, setResult] = useState<AuthorizeResult | null>(null);
  const [verification, setVerification] = useState<VerificationLink | null>(null);
  const [error, setError] = useState<string | null>(null);

  const template = useMemo(
    () => TEMPLATES.find((item) => item.id === templateId) ?? TEMPLATES[0]!,
    [templateId],
  );

  useEffect(() => {
    setPolicySaved(false);
    setAgentKey(null);
    setResult(null);
    setVerification(null);
    setError(null);
  }, [environmentId]);

  const createEnvironment = useMutation({
    mutationFn: () =>
      api<{ id: string }>("/v1/environments", {
        method: "POST",
        body: JSON.stringify({ name: environmentName }),
      }),
    onSuccess: async (environment) => {
      await refresh();
      setEnvironmentId(environment.id);
      await queryClient.invalidateQueries();
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  const savePolicy = useMutation({
    mutationFn: () =>
      api(`/v1/policies/${encodeURIComponent(template.id)}${environmentQuery(environmentId)}`, {
        method: "PUT",
        body: JSON.stringify({
          version: 1,
          name: template.name,
          mode: "enforce",
          fail_open: false,
          grants: template.grants,
          limits: {},
        }),
      }),
    onSuccess: () => {
      setPolicySaved(true);
      setError(null);
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  const createKey = useMutation({
    mutationFn: () =>
      api<{ key: string }>(`/v1/agent-keys${environmentQuery(environmentId)}`, {
        method: "POST",
        body: JSON.stringify({ name: "quickstart-agent" }),
      }),
    onSuccess: (data) => {
      setAgentKey(data.key);
      setError(null);
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  const runTest = useMutation({
    mutationFn: async () => {
      if (!agentKey) throw new Error("Create an agent key first");
      const action = await api<AuthorizeResult>("/v1/authorize", {
        method: "POST",
        headers: { "x-api-key": agentKey },
        body: JSON.stringify({
          agentId: "quickstart-agent",
          userId: me.user.id,
          tool: template.test.tool,
          intent: "Quickstart policy check; this is a denial test and does not call a provider.",
          args: template.test.args,
          riskClass: template.test.riskClass,
          agentMeta: { agentVersion: "quickstart", environment: "quickstart" },
        }),
      });
      const link = await api<VerificationLink>("/v1/verification-links", {
        method: "POST",
        body: JSON.stringify({ actionId: action.actionId }),
      });
      return { action, link };
    },
    onSuccess: ({ action, link }) => {
      setResult(action);
      setVerification(link);
      setError(null);
      void queryClient.invalidateQueries({ queryKey: ["actions"] });
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  const endpoint = window.location.origin;
  const snippet = `curl -X POST ${endpoint}/v1/authorize \\
  -H "x-api-key: $TESSERA_API_KEY" \\
  -H "content-type: application/json" \\
  -d '{
    "agentId": "my-agent",
    "tool": "${template.example.tool}",
    "intent": "describe the action",
    "args": ${JSON.stringify(template.example.args)}
  }'`;
  const step = !environmentId ? 1 : !policySaved ? 2 : !agentKey ? 3 : 4;

  return (
    <>
      <PageHeader
        title="Quickstart"
        subtitle="Create a policy, connect an agent, and produce your first signed proof in a few minutes."
        actions={<Link className="tf-btn" to="/proof/">View proof index</Link>}
      />
      <ErrorBanner message={error} />

      <Card style={{ marginBottom: 16 }}>
        <div className="tf-onboarding-steps" aria-label="Quickstart progress">
          <Step number={1} label="Environment" active={step === 1} done={Boolean(environmentId)} />
          <Step number={2} label="Policy" active={step === 2} done={policySaved} />
          <Step number={3} label="Agent key" active={step === 3} done={Boolean(agentKey)} />
          <Step number={4} label="First proof" active={step === 4} done={Boolean(result)} />
        </div>
      </Card>

      <Card style={{ marginBottom: 16 }}>
        <div className="tf-section-kicker">1 · Environment</div>
        {environmentId ? (
          <p className="tf-muted" style={{ margin: 0 }}>
            Using <strong>{me.environments.find((environment) => environment.id === environmentId)?.name ?? "selected environment"}</strong>.
          </p>
        ) : (
          <div className="tf-actions" style={{ marginTop: 10 }}>
            <input
              className="tf-input"
              value={environmentName}
              onChange={(event) => setEnvironmentName(event.target.value)}
              placeholder="Environment name"
              style={{ maxWidth: 280 }}
            />
            <Button
              variant="primary"
              onClick={() => createEnvironment.mutate()}
              disabled={createEnvironment.isPending || !environmentName.trim()}
            >
              {createEnvironment.isPending ? "Creating…" : "Create environment"}
            </Button>
          </div>
        )}
      </Card>

      <Card style={{ marginBottom: 16 }}>
        <div className="tf-section-kicker">2 · Policy</div>
        <p className="tf-muted">Start with a useful boundary. You can edit the full policy later.</p>
        <div className="tf-template-grid">
          {TEMPLATES.map((item) => (
            <button
              key={item.id}
              className={`tf-template-card ${item.id === template.id ? "active" : ""}`}
              onClick={() => {
                setTemplateId(item.id);
                setPolicySaved(false);
                setResult(null);
                setVerification(null);
              }}
              disabled={!environmentId}
            >
              <strong>{item.name}</strong>
              <span>{item.description}</span>
            </button>
          ))}
        </div>
        <div className="tf-actions" style={{ marginTop: 14 }}>
          <Button
            variant="primary"
            onClick={() => savePolicy.mutate()}
            disabled={!environmentId || savePolicy.isPending}
          >
            {savePolicy.isPending ? "Saving…" : policySaved ? "Save policy" : "Create policy"}
          </Button>
          {policySaved ? <Badge tone="ok">Policy ready</Badge> : null}
        </div>
      </Card>

      <Card style={{ marginBottom: 16 }}>
        <div className="tf-section-kicker">3 · Agent key</div>
        <p className="tf-muted">Owner-bound keys are preferred. This key is shown once.</p>
        <div className="tf-actions">
          <Button
            onClick={() => createKey.mutate()}
            disabled={!policySaved || createKey.isPending}
          >
            {createKey.isPending ? "Creating…" : agentKey ? "Create another key" : "Create agent key"}
          </Button>
        </div>
        {agentKey ? (
          <div style={{ marginTop: 14 }}>
            <CopyRow value={agentKey} />
            <p className="tf-muted" style={{ fontSize: 12, marginTop: 8 }}>
              Keep this out of source control. It is scoped to this environment.
            </p>
          </div>
        ) : null}
      </Card>

      <Card style={{ marginBottom: 16 }}>
        <div className="tf-section-kicker">4 · First proof</div>
        <p className="tf-muted">
          Send a deliberately denied request through the selected policy. It creates a signed proof and
          never calls a provider.
        </p>
        <Button
          variant="primary"
          onClick={() => runTest.mutate()}
          disabled={!agentKey || runTest.isPending || Boolean(result)}
        >
          {runTest.isPending ? "Creating proof…" : result ? "Proof created" : "Create test proof"}
        </Button>
        {result ? (
          <div className="tf-quickstart-result" style={{ marginTop: 16 }}>
            <p>
              <Badge tone={result.decision === "deny" ? "warn" : "ok"}>{result.decision}</Badge>{" "}
              <Link to={`/actions/${result.actionId}`}>Open action {result.actionId.slice(0, 8)}…</Link>
            </p>
            <p className="tf-muted">
              This is a signed policy check. Denial is expected for the quickstart fixture.
            </p>
            {verification ? (
              <div style={{ marginTop: 10 }}>
                <CopyRow value={verification.url} />
                <a className="tf-btn" href={verification.url} target="_blank" rel="noreferrer" style={{ marginTop: 10 }}>
                  Open verification page
                </a>
              </div>
            ) : null}
          </div>
        ) : null}
      </Card>

      <Card>
        <div className="tf-section-kicker">Use it from your agent</div>
        <p className="tf-muted">
          Replace the placeholder with the key above. For a successful action, use the provider
          integration guide and keep the policy mode at <code>enforce</code>.
        </p>
        <pre className="tf-code-block">{snippet}</pre>
        <p className="tf-muted" style={{ fontSize: 12 }}>
          To create an allowed broker-observed proof, use the Stripe proxy path in
          <code> docs/golden-path.md</code> after connecting test-mode credentials.
        </p>
      </Card>
    </>
  );
}

function Step({
  number,
  label,
  active,
  done,
}: {
  number: number;
  label: string;
  active: boolean;
  done: boolean;
}) {
  return (
    <div className={`tf-onboarding-step ${active ? "active" : ""} ${done ? "done" : ""}`}>
      <span>{done ? "✓" : number}</span>
      <strong>{label}</strong>
    </div>
  );
}
