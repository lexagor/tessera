import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, test, vi } from "vitest";

import { LoginPage } from "../src/pages/Login";
import { PublicEvidencePage } from "../src/pages/PublicEvidence";
import { PublicVerifyPage } from "../src/pages/PublicVerify";

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
