import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, test, vi } from "vitest";

import { AnalyticsPage } from "../src/pages/Analytics";
import { IntegrationsPage } from "../src/pages/Integrations";
import { LoginPage } from "../src/pages/Login";
import { PublicEvidencePage } from "../src/pages/PublicEvidence";
import { PublicVerifyPage } from "../src/pages/PublicVerify";

vi.mock("../src/App", () => ({
  useWorkspace: () => ({
    environmentId: "env_1",
    setEnvironmentId: vi.fn(),
    refresh: vi.fn(),
    me: {
      user: { id: "user_1", email: "dev@tessera.local", name: "Dev User" },
      org: { id: "org_1", name: "Acme", slug: "acme", plan: "team" },
      role: "owner",
      environments: [{ id: "env_1", name: "Production", slug: "production", broker_tenant: "acme-production" }],
    },
  }),
}));

function queryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
}

function response(body: unknown): Response {
  return {
    ok: true,
    status: 200,
    text: async () => JSON.stringify(body),
  } as Response;
}

afterEach(() => vi.unstubAllGlobals());

describe("portal pages", () => {
  test("login shows dev sign-in when dev auth is enabled", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => response({ devAuth: true, oidc: false })),
    );
    render(
      <QueryClientProvider client={queryClient()}>
        <LoginPage />
      </QueryClientProvider>,
    );
    expect(await screen.findByText("Dev sign in")).toBeInTheDocument();
  });

  test("public evidence renders a reviewer report", async () => {
    const summary = {
      version: 1,
      generatedAt: "2026-11-12T10:00:00Z",
      orgName: "Acme",
      environmentName: "Production",
      scope: { type: "environment", agentId: null },
      window: { since: "2026-10-13T00:00:00Z", until: "2026-11-12T00:00:00Z" },
      recipients: ["security@example.com"],
      readiness: {
        score: 82,
        status: "partial",
        explanation: "Most controls have evidence, but gaps remain.",
        covered: 11,
        partial: 6,
        gap: 0,
        controls: 17,
      },
      inventory: {
        actions: 56,
        allowed: 52,
        denied: 4,
        completed: 52,
        failed: 2,
        verified: 56,
        agents: 6,
        policies: 1,
        reviews: 2,
        transitions: 2,
        verificationLinks: 1,
        agentKeys: 3,
        evidencePacks: 2,
        receipts: 56,
        anchors: 0,
      },
      signals: [],
      frameworks: [
        {
          id: "soc2",
          name: "SOC 2",
          description: "Security evidence.",
          controls: [],
          covered: 0,
          partial: 0,
          gap: 0,
          readiness: 0,
        },
      ],
      gaps: ["1 review still needs a decision."],
      notes: ["Evidence coverage is not a certification."],
      delta: null,
      policies: [],
      records: [],
      reviews: { total: 0, pending: 0, approved: 0, rejected: 0, items: [] },
      transitions: [],
      verificationLinks: [],
      proof: {
        chainsVerified: true,
        keyEventsVerified: true,
        chainReceipts: 56,
        anchors: 0,
        anchorLatest: null,
        unanchoredAgents: 1,
      },
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        response({
          pack: {
            id: "pack_1",
            createdAt: "2026-11-12T10:00:00Z",
            expiresAt: null,
            shareExpiresAt: "2026-12-12T10:00:00Z",
            summary,
          },
          org: { name: "Acme" },
          environment: { name: "Production" },
          downloadUrl: "/download",
          reportUrl: "/report",
          verifyUrl: "https://verify.example",
          securityContact: "security@example.com",
        }),
      ),
    );
    render(
      <QueryClientProvider client={queryClient()}>
        <MemoryRouter initialEntries={["/evidence/share/token"]}>
          <Routes>
            <Route path="/evidence/share/:token" element={<PublicEvidencePage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    expect(await screen.findByText("Production evidence pack")).toBeInTheDocument();
    expect(screen.getByText("Reviewer report")).toBeInTheDocument();
  });

  test("analytics page answers the security questions", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        response({
          window: { since: "2026-11-01T00:00:00Z", until: "2026-11-12T00:00:00Z", range: "14d", days: 14 },
          totals: {
            actions: 63, allowed: 59, denied: 4, completed: 63, failed: 2, verified: 63,
            brokerObserved: 0, agentReported: 59, agents: 7, governed: 63, ungoverned: 0,
            policies: 5, reviews: 2, pendingReviews: 1, verificationLinks: 1, evidencePacks: 2,
          },
          rates: { allow: 0.94, deny: 0.06, verifiedOutcome: 1, policyCoverage: 1 },
          series: [{ day: "2026-11-12", actions: 4, allowed: 3, denied: 1, failed: 0, verified: 4, brokerObserved: 0, agentReported: 3 }],
          tools: [{ tool: "stripe.refunds.create", actions: 4, allowed: 3, denied: 1, failed: 0, verified: 4 }],
          policies: [{ policyId: "demo-baseline", actions: 4, denied: 1, verified: 4 }],
          heatmap: {
            agents: [{ agentId: "billing-agent", actions: 4, denied: 1 }],
            days: ["2026-11-12"],
            cells: [{ agentId: "billing-agent", day: "2026-11-12", actions: 4, denied: 1 }],
          },
          verification: { sample: 63, averageSeconds: 32, p50Seconds: 30, p95Seconds: 60 },
        }),
      ),
    );
    render(
      <QueryClientProvider client={queryClient()}>
        <MemoryRouter initialEntries={["/analytics"]}>
          <Routes>
            <Route path="/analytics" element={<AnalyticsPage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    expect(await screen.findByRole("heading", { name: "Analytics" })).toBeInTheDocument();
    expect(await screen.findByText("Actions over time")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Policy coverage" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Mean time to verification" })).toBeInTheDocument();
  });

  test("integrations page shows coverage and credential posture", async () => {
    const stripeProvider = {
      id: "stripe",
      name: "Stripe",
      category: "Payments",
      description: "Refunds and charges.",
      authMode: "broker_managed",
      credentialFields: [{ key: "secretKey", label: "Restricted key", secret: true }],
      scopes: [{ id: "refunds", label: "Create refunds", resource: "stripe:refunds.create", description: "Refund", risk: "high" }],
      sample: { tool: "stripe.refunds.create", args: {}, intent: "check" },
      docsUrl: "https://docs.example/stripe",
      maturity: "ga",
      color: "#635bff",
    };
    const githubProvider = {
      ...stripeProvider,
      id: "github",
      name: "GitHub",
      category: "Code & delivery",
      description: "Issues and pull requests.",
      scopes: [{ id: "issues", label: "Create issues", resource: "github:issues.create", description: "Issue", risk: "medium" }],
      sample: { tool: "github.issues.create", args: {}, intent: "check" },
      color: "#24292f",
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        response({
          providers: [stripeProvider, githubProvider],
          items: [
            {
              id: "int_1",
              provider: "stripe",
              providerName: "Stripe",
              providerCategory: "Payments",
              name: "Stripe billing",
              status: "connected",
              authMode: "broker_managed",
              scopes: stripeProvider.scopes,
              owner: { id: "user_1", email: "dev@tessera.local", name: "Dev User" },
              environment: { id: "env_1", name: "Production" },
              hasCredential: false,
              credentialHint: null,
              metadata: {},
              policyId: "integration-stripe",
              testActionId: "action_1",
              lastSyncAt: "2026-11-12T10:00:00Z",
              lastTestedAt: "2026-11-12T10:00:00Z",
              lastTestOk: true,
              lastTestMessage: "Broker-managed connection.",
              createdAt: "2026-11-12T10:00:00Z",
              updatedAt: "2026-11-12T10:00:00Z",
            },
          ],
        }),
      ),
    );
    render(
      <QueryClientProvider client={queryClient()}>
        <MemoryRouter initialEntries={["/integrations"]}>
          <Routes>
            <Route path="/integrations" element={<IntegrationsPage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    expect(await screen.findByRole("heading", { name: "Integrations" })).toBeInTheDocument();
    expect(await screen.findByText("Stripe")).toBeInTheDocument();
    expect(screen.getByText("GitHub")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Test connection" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Rotate credential" })).toBeInTheDocument();
  });

  test("public verify renders a valid action record", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        response({
          expiresAt: "2026-12-01T00:00:00Z",
          verification: { valid: true, errors: [], recovered: "0xabc" },
          records: {
            authorization: {
              agent: "billing-agent",
              user: "user_1",
              principal: { principalId: "user_1" },
              call: { tool: "stripe.refunds.create" },
              policy: {},
              credential: {},
              authorization: { decision: "allow" },
            },
            outcome: null,
          },
        }),
      ),
    );
    render(
      <QueryClientProvider client={queryClient()}>
        <MemoryRouter initialEntries={["/verify/token"]}>
          <Routes>
            <Route path="/verify/:token" element={<PublicVerifyPage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    expect(await screen.findByText("Valid action record")).toBeInTheDocument();
  });
});
