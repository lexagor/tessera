import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";

import { api, type ActionDetail, type VerificationLink } from "../api";
import {
  Badge,
  Button,
  Card,
  CopyRow,
  ErrorBanner,
  PageHeader,
  formatDate,
  shortHash,
} from "@tessera/ui";

export function ActionDetailPage() {
  const { actionId = "" } = useParams();
  const [error, setError] = useState<string | null>(null);
  const [link, setLink] = useState<VerificationLink | null>(null);
  const [showRaw, setShowRaw] = useState(false);

  const query = useQuery({
    queryKey: ["action", actionId],
    queryFn: () => api<ActionDetail>(`/v1/actions/${encodeURIComponent(actionId)}`),
  });

  const createLink = useMutation({
    mutationFn: () =>
      api<VerificationLink>("/v1/verification-links", {
        method: "POST",
        body: JSON.stringify({ actionId }),
      }),
    onSuccess: (data) => {
      setLink(data);
      setError(null);
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  if (query.isLoading) return <Card>Loading action…</Card>;
  if (query.isError || !query.data) {
    return <ErrorBanner message={query.error instanceof Error ? query.error.message : "Action not found"} />;
  }

  const action = query.data;
  const verified = action.verification?.valid === true;
  const verificationKnown = action.verification !== null;
  const outcome = action.payload.outcome as Record<string, any> | null | undefined;
  const authorization = action.payload.authorization as Record<string, any> | undefined;
  const principal = authorization?.principal as Record<string, any> | undefined;
  const policy = authorization?.policy as Record<string, any> | undefined;
  const credential = authorization?.credential as Record<string, any> | undefined;

  return (
    <>
      <PageHeader
        title={action.tool}
        subtitle={`${action.agentId} · ${formatDate(action.createdAt)}`}
        actions={
          <>
            <Link className="tf-btn ghost" to="/actions">Back to actions</Link>
            <a
              className="tf-btn ghost"
              href={`/v1/actions/${encodeURIComponent(actionId)}/agent-receipt`}
            >
              Agent Receipt
            </a>
            <Button
              variant="primary"
              onClick={() => createLink.mutate()}
              disabled={createLink.isPending}
            >
              {createLink.isPending ? "Creating…" : "Create verification link"}
            </Button>
          </>
        }
      />

      <ErrorBanner message={error} />

      {link ? (
        <Card className="tf-grid" style={{ marginBottom: 16 }}>
          <div className="tf-actions" style={{ justifyContent: "space-between" }}>
            <div>
              <strong>Verification link created</strong>
              <div className="tf-muted">
                Expires {formatDate(link.expiresAt)}. Anyone with the link can verify this action
                without signing in.
              </div>
            </div>
            <Badge tone="ok">ready</Badge>
          </div>
          <CopyRow value={link.url} />
        </Card>
      ) : null}

      <div className="tf-grid tf-grid-3" style={{ marginBottom: 16 }}>
        <Card>
          <div className="tf-kpi-label">Decision</div>
          <div style={{ marginTop: 8 }}>
            <Badge tone={action.decision === "allow" ? "ok" : "bad"}>{action.decision}</Badge>
          </div>
        </Card>
        <Card>
          <div className="tf-kpi-label">Outcome</div>
          <div style={{ marginTop: 8 }}>
            <Badge tone={action.outcomeStatus === "success" ? "ok" : action.outcomeStatus ? "warn" : "muted"}>
              {action.outcomeStatus || "pending"}
            </Badge>
          </div>
        </Card>
        <Card>
          <div className="tf-kpi-label">Verification</div>
          <div style={{ marginTop: 8 }}>
            {verificationKnown ? (
              <Badge tone={verified ? "ok" : "bad"}>{verified ? "valid" : "invalid"}</Badge>
            ) : (
              <Badge tone="muted">not checked</Badge>
            )}
          </div>
        </Card>
      </div>

      <Card style={{ marginBottom: 16 }}>
        <h2 style={{ margin: 0, fontSize: 18 }}>Binding</h2>
        <div className="tf-grid tf-grid-3" style={{ marginTop: 14 }}>
          <Fact label="Agent" value={action.agentId} mono />
          <Fact label="Principal" value={action.principalId} mono />
          <Fact label="Authority method" value={principal?.verificationMethod ?? "—"} />
          <Fact label="Policy" value={`${action.policyId} v${action.policyVersion}`} />
          <Fact label="Policy hash" value={shortHash(action.policyHash, 12)} mono />
          <Fact label="Credential issuer" value={action.credentialIssuer ?? "—"} />
          <Fact label="Credential thumbprint" value={shortHash(action.credentialThumbprint, 12)} mono />
          <Fact label="Action id" value={shortHash(action.actionId, 12)} mono />
          <Fact label="Receipt id" value={shortHash(action.receiptId, 12)} mono />
          <Fact
            label="Outcome source"
            value={String(outcome?.outcome?.source ?? "not recorded")}
          />
        </div>
      </Card>

      <div className="tf-grid" style={{ gridTemplateColumns: "1fr 1fr" }}>
        <Card>
          <h2 style={{ margin: 0, fontSize: 18 }}>Authorization record</h2>
          <p className="tf-muted">Signed before execution. This is the policy decision and the credential binding.</p>
          <RecordFacts record={authorization} />
        </Card>
        <Card>
          <h2 style={{ margin: 0, fontSize: 18 }}>Outcome record</h2>
          <p className="tf-muted">
            Signed after execution. The broker records proxy outcomes itself; direct credentials
            report their own outcome.
          </p>
          {outcome ? <RecordFacts record={outcome} /> : <p className="tf-muted">No outcome recorded yet.</p>}
        </Card>
      </div>

      <Card style={{ marginTop: 16 }}>
        <div className="tf-actions" style={{ justifyContent: "space-between" }}>
          <h2 style={{ margin: 0, fontSize: 18 }}>Raw evidence</h2>
          <Button variant="ghost" onClick={() => setShowRaw((value) => !value)}>
            {showRaw ? "Hide JSON" : "Show JSON"}
          </Button>
        </div>
        {showRaw ? (
          <pre className="tf-code" style={{ marginTop: 12 }}>
            {JSON.stringify(action.payload, null, 2)}
          </pre>
        ) : null}
        {action.verification?.errors.length ? (
          <div className="tf-error" style={{ marginTop: 12 }}>
            {action.verification.errors.join(" · ")}
          </div>
        ) : null}
        {verificationKnown ? (
          <p className="tf-muted" style={{ marginTop: 12, marginBottom: 0 }}>
            Recovered signer: <span className="tf-mono">{action.verification?.recovered ?? "—"}</span>
            {policy?.policyHash ? (
              <> · policy hash <span className="tf-mono">{shortHash(policy.policyHash, 12)}</span></>
            ) : null}
          </p>
        ) : null}
      </Card>
    </>
  );
}

function Fact({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div className="tf-kpi-label">{label}</div>
      <div className={mono ? "tf-mono" : ""} style={{ marginTop: 4 }}>{value}</div>
    </div>
  );
}

function RecordFacts({ record }: { record: Record<string, any> | undefined }) {
  if (!record) return <p className="tf-muted">—</p>;
  return (
    <div className="tf-list">
      <Row label="Status" value={String(record.outcome?.status ?? record.grant?.status ?? "—")} />
      <Row label="Tool" value={String(record.call?.tool ?? "—")} />
      <Row label="Args hash" value={shortHash(record.call?.argsHash, 14)} mono />
      <Row label="Result hash" value={shortHash(record.call?.resultHash, 14)} mono />
      <Row label="Timestamp" value={formatDate(record.ts)} />
      <Row label="Prev" value={shortHash(record.prev, 14)} mono />
      <Row
        label="Authorization receipt"
        value={shortHash(record.authorizationReceiptId ?? record.prev, 14)}
        mono
      />
      <Row label="Signer key" value={shortHash(record.attestation?.signerKeyId, 14)} mono />
    </div>
  );
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="tf-list-row">
      <span className="tf-muted">{label}</span>
      <span className={mono ? "tf-mono" : ""}>{value}</span>
    </div>
  );
}
