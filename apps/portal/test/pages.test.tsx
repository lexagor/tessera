import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, test, vi } from "vitest";

import { LoginPage } from "../src/pages/Login";
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
