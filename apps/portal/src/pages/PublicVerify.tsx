import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useParams } from "react-router-dom";

import { api } from "../api";
import {
  Badge,
  Button,
  Card,
  CopyRow,
  ErrorBanner,
  formatDate,
  shortHash,
} from "@tessera/ui";

interface PublicVerification {
  expiresAt: string;
  verification: {
    valid: boolean;
    errors: string[];
    recovered?: string;
    matchesExpected?: boolean;
  };
  records: {
    authorization?: Record<string, any>;
    outcome?: Record<string, any> | null;
  };
}

export function PublicVerifyPage() {
  const { token = "" } = useParams();
  const [showRaw, setShowRaw] = useState(false);
  const query = useQuery({
    queryKey: ["public-verify", token],
    queryFn: () => api<PublicVerification>(`/v1/public/verify/${encodeURIComponent(token)}`),
    retry: false,
  });

  if (query.isLoading) {
    return <div className="tf-login"><div className="tf-login-card">Verifying record…</div></div>;
  }
  if (query.isError || !query.data) {
    return (
      <div className="tf-login">
        <div className="tf-login-card">
          <p className="tf-kpi-label">Tessera verification</p>
          <h1>Link unavailable</h1>
          <ErrorBanner message={query.error instanceof Error ? query.error.message : "This verification link is invalid or expired."} />
        </div>
      </div>
    );
  }

  const result = query.data;
  const authorization = result.records.authorization ?? {};
  const outcome = result.records.outcome;
  const principal = authorization.principal ?? {};
  const policy = authorization.policy ?? {};
  const credential = authorization.credential ?? {};
  const call = authorization.call ?? {};
  const valid = result.verification.valid;

  return (
    <div className="tf-login" style={{ alignItems: "start", paddingTop: 48 }}>
      <div style={{ width: "min(920px, 100%)" }} className="tf-grid">
        <Card>
          <div className="tf-actions" style={{ justifyContent: "space-between" }}>
            <div>
              <p className="tf-kpi-label">Tessera verification</p>
              <h1 style={{ margin: "6px 0", fontSize: 30 }}>
                {valid ? "Valid action record" : "Record could not be verified"}
              </h1>
            </div>
            <Badge tone={valid ? "ok" : "bad"}>{valid ? "valid" : "invalid"}</Badge>
          </div>
          <p className="tf-muted">
            {String(authorization.agent ?? "The agent")} acted for{" "}
            <strong>{String(principal.principalId ?? authorization.user ?? "a principal")}</strong>{" "}
            through <span className="tf-inline-code">{String(call.tool ?? "a tool")}</span>.
          </p>
          <div className="tf-grid tf-grid-3">
            <Fact label="Decision" value={String(authorization.authorization?.decision ?? "—")} />
            <Fact label="Outcome" value={String(outcome?.outcome?.status ?? "not recorded")} />
            <Fact label="Outcome source" value={String(outcome?.outcome?.source ?? "—")} />
            <Fact label="Policy" value={`${String(policy.policyId ?? "—")} v${String(policy.policyVersion ?? "—")}`} />
            <Fact label="Credential" value={String(credential.credentialType ?? credential.issuer ?? "—")} />
            <Fact label="TTL" value={credential.ttlSeconds ? `${credential.ttlSeconds}s` : "—"} />
            <Fact label="Signed" value={formatDate(authorization.ts)} />
          </div>
          {result.verification.errors.length ? (
            <div className="tf-error">{result.verification.errors.join(" · ")}</div>
          ) : null}
          <p className="tf-muted" style={{ marginBottom: 0 }}>
            Link expires {formatDate(result.expiresAt)}. Recovered signer:{" "}
            <span className="tf-mono">{shortHash(result.verification.recovered, 14)}</span>
          </p>
        </Card>

        <Card>
          <div className="tf-actions" style={{ justifyContent: "space-between" }}>
            <h2 style={{ margin: 0, fontSize: 18 }}>Portable evidence</h2>
            <Button variant="ghost" onClick={() => setShowRaw((value) => !value)}>
              {showRaw ? "Hide JSON" : "Show JSON"}
            </Button>
          </div>
          <p className="tf-muted">
            This record can be verified offline with the open-source Tessera verifier. The
            cryptographic signature binds the agent, principal, policy, credential, call, and
            outcome.
          </p>
          {showRaw ? (
            <pre className="tf-code">{JSON.stringify(result.records, null, 2)}</pre>
          ) : (
            <CopyRow value={JSON.stringify(result.records, null, 2)} />
          )}
        </Card>

        <Card>
          <h2 style={{ margin: 0, fontSize: 18 }}>What this proves</h2>
          <ul className="tf-muted" style={{ margin: "10px 0 0", paddingLeft: 18 }}>
            <li>The broker authorized this exact tool call under the recorded policy version.</li>
            <li>The credential issued was scoped and bound to the arguments hash.</li>
            <li>The linked outcome record was signed after execution and chains to the authorization.</li>
            <li>Any modification to the record changes the payload hash and invalidates the signature.</li>
          </ul>
        </Card>
      </div>
    </div>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="tf-kpi-label">{label}</div>
      <div style={{ marginTop: 4 }}>{value}</div>
    </div>
  );
}
