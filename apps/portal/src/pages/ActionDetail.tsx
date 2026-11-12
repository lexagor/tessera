import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
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
import { RiskBadge, Stat } from "../components/Charts";
import { riskForTool } from "../lib/risk";

export function ActionDetailPage() {
  const { actionId = "" } = useParams();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const [link, setLink] = useState<VerificationLink | null>(null);
  const [showRaw, setShowRaw] = useState(false);

  const query = useQuery({
    queryKey: ["action", actionId],
    queryFn: () => api<ActionDetail>(`/v1/actions/${encodeURIComponent(actionId)}`),
  });

  const requestReview = useMutation({
    mutationFn: () =>
      api(`/v1/actions/${encodeURIComponent(actionId)}/review`, {
        method: "POST",
        body: JSON.stringify({ reason: "High-risk action needs a human decision" }),
      }),
    onSuccess: async () => {
      setError(null);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["action", actionId] }),
        queryClient.invalidateQueries({ queryKey: ["reviews"] }),
      ]);
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
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
  const call = authorization?.call as Record<string, any> | undefined;
  const risk = riskForTool(action.tool, action.decision);
  const denied = action.decision === "deny";
  const outcomeRef = outcome?.outcome as Record<string, any> | undefined;
  const outcomeStatus = outcomeRef?.status ?? action.outcomeStatus ?? "pending";
  const outcomeSource = outcomeRef?.source ?? "not recorded";
  const signer = action.verification?.recovered;
  const enforcement = denied
    ? { tone: "bad" as const, label: "Policy denied" }
    : outcomeSource === "broker_observed"
      ? { tone: "ok" as const, label: "Level 1 · broker-observed" }
      : credential?.credentialType === "broker_grant"
        ? { tone: "ok" as const, label: "Level 1 · broker-held" }
        : credential
          ? { tone: "warn" as const, label: "Level 2 · scoped credential" }
          : { tone: "warn" as const, label: "Caller-asserted authority" };

  const timeline = [
    {
      label: "Principal authority",
      detail: principal
        ? `${principal.principalId} · ${principal.verificationMethod}`
        : "Caller-asserted principal",
      state: principal ? "done" : "pending",
    },
    {
      label: "Policy evaluated",
      detail: `${action.policyId || "no policy"} v${action.policyVersion} · ${policy?.reasonCode ?? action.decision}`,
      state: "done",
    },
    {
      label: action.decision === "deny" ? "Credential withheld" : "Credential issued",
      detail:
        action.decision === "deny"
          ? "No credential released"
          : `${credential?.issuer ?? action.credentialIssuer ?? "issuer"} · ${credential?.ttlSeconds ?? "—"}s · ${credential?.singleUse ? "single use" : "reusable"}`,
      state: action.decision === "deny" ? "blocked" : "done",
    },
    {
      label: denied ? "Tool call not executed" : "Tool call",
      detail: denied
        ? "Policy denied the request before execution"
        : `${call?.tool ?? action.tool} · args ${shortHash(call?.argsHash ?? "—", 10)}`,
      state: denied ? "blocked" : "done",
    },
    {
      label: denied ? "Outcome not recorded" : "Outcome observed",
      detail: denied ? "No execution took place" : `${outcomeStatus} · ${outcomeSource}`,
      state: denied
        ? "blocked"
        : outcomeStatus === "failure"
          ? "failed"
          : outcomeStatus === "pending"
            ? "pending"
            : "done",
    },
    {
      label: "Signed and chained",
      detail: signer ? `Signed by ${shortHash(signer, 12)} · ${shortHash(action.receiptId, 12)}` : "Signature not checked",
      state: verified ? "verified" : verificationKnown ? "failed" : "pending",
    },
  ];

  return (
    <>
      <PageHeader
        title={action.tool}
        subtitle={`${action.agentId} · ${formatDate(action.createdAt)}`}
        actions={
          <>
            <Badge tone={enforcement.tone}>{enforcement.label}</Badge>
            <Link className="tf-btn ghost" to="/actions">Back to actions</Link>
            <a className="tf-btn ghost" href={`/v1/actions/${encodeURIComponent(actionId)}/agent-receipt`}>
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

      <div className={`tf-verify-banner ${verified ? "ok" : verificationKnown ? "bad" : "pending"}`}>
        <div className="tf-verify-mark">{verified ? "✓" : verificationKnown ? "!" : "·"}</div>
        <div className="tf-verify-copy">
          <strong>
            {verified
              ? "Independently verified"
              : verificationKnown
                ? "Signature check failed"
                : "Verification not checked"}
          </strong>
          <span>
            {verified
              ? "This record was checked against the broker signature and chain."
              : verificationKnown
                ? action.verification?.errors.join(" · ")
                : "Open this record with the verifier to check its signature and chain."}
          </span>
        </div>
        {signer ? <span className="tf-mono tf-muted">{shortHash(signer, 16)}</span> : null}
        <Badge tone={verified ? "ok" : verificationKnown ? "bad" : "muted"}>
          {verified ? "verified" : verificationKnown ? "invalid" : "unchecked"}
        </Badge>
      </div>

      <div className={`tf-review-banner ${action.review?.status ?? "none"}`}>
        <div>
          <strong>
            {action.review?.status === "pending"
              ? "Waiting for review"
              : action.review?.status === "approved"
                ? "Reviewed and approved"
                : action.review?.status === "rejected"
                  ? "Review rejected"
                  : "No review requested"}
          </strong>
          <span>
            {action.review?.status === "pending"
              ? action.review.reason ?? "A reviewer needs to make a decision."
              : action.review?.resolution_note
                ? action.review.resolution_note
                : "Send a high-risk action to the review queue for a human decision."}
          </span>
        </div>
        {action.review ? (
          <Link className="tf-btn ghost" to="/reviews">Open review queue</Link>
        ) : (
          <Button variant="ghost" onClick={() => requestReview.mutate()} disabled={requestReview.isPending}>
            {requestReview.isPending ? "Requesting…" : "Request review"}
          </Button>
        )}
      </div>

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

      <div className="tf-stat-row">
        <Card>
          <Stat label="Decision" value={<Badge tone={action.decision === "allow" ? "ok" : "bad"}>{action.decision}</Badge>} note={policy?.reasonCode ?? "policy decision"} />
        </Card>
        <Card>
          <Stat label="Risk" value={<RiskBadge level={risk.level} />} note={policy?.policyId ?? "risk class"} tone={risk.level === "critical" ? "danger" : risk.level === "high" ? "warning" : undefined} />
        </Card>
        <Card>
          <Stat label="Outcome" value={<Badge tone={outcomeStatus === "success" ? "ok" : outcomeStatus === "failure" ? "warn" : "muted"}>{outcomeStatus}</Badge>} note={outcomeSource} />
        </Card>
        <Card>
          <Stat label="Receipt chain" value={verified ? "linked" : "—"} note={shortHash(action.receiptId, 12)} />
        </Card>
      </div>

      <div className="tf-grid" style={{ marginTop: 18, gridTemplateColumns: "1.1fr .9fr", alignItems: "start" }}>
        <Card>
          <h2 style={{ margin: 0, fontSize: 18 }}>Evidence timeline</h2>
          <p className="tf-muted" style={{ margin: "3px 0 18px" }}>From delegated authority to a verifiable outcome.</p>
          <div className="tf-timeline">
            {timeline.map((step) => (
              <div className={`tf-timeline-step ${step.state}`} key={step.label}>
                <div className="tf-timeline-rail"><span /></div>
                <div className="tf-timeline-copy">
                  <strong>{step.label}</strong>
                  <span>{step.detail}</span>
                </div>
              </div>
            ))}
          </div>
        </Card>

        <Card>
          <h2 style={{ margin: 0, fontSize: 18 }}>Authority graph</h2>
          <p className="tf-muted" style={{ margin: "3px 0 18px" }}>The chain of authority for this exact action.</p>
          <div className="tf-authority-graph">
            <GraphNode label="Principal" value={action.principalId} />
            <GraphArrow />
            <GraphNode label="Agent" value={action.agentId} />
            <GraphArrow />
            <GraphNode label="Credential" value={action.credentialIssuer ?? "none"} />
            <GraphArrow />
            <GraphNode label="Action" value={action.tool.split(".").pop() ?? action.tool} />
            <GraphArrow />
            <GraphNode label="Outcome" value={outcomeStatus} />
          </div>
          <div className="tf-authority-note">
            Every node is bound to the signed receipt. The verifier checks the same graph without trusting Tessera.
          </div>
        </Card>
      </div>

      <div className="tf-grid" style={{ marginTop: 18, gridTemplateColumns: "1fr 1fr" }}>
        <Card>
          <h2 style={{ margin: 0, fontSize: 18 }}>Policy decision</h2>
          <div className="tf-grid tf-grid-3" style={{ marginTop: 14 }}>
            <Fact label="Policy" value={action.policyId || "—"} />
            <Fact label="Version" value={String(action.policyVersion)} />
            <Fact label="Decision" value={action.decision} />
            <Fact label="Principal" value={action.principalId} mono />
            <Fact label="Authority" value={String(principal?.authorityRef ?? "caller asserted")} mono />
            <Fact label="Authority method" value={String(principal?.verificationMethod ?? "—")} />
            <Fact label="Args hash" value={shortHash(call?.argsHash, 16)} mono />
            <Fact label="Policy hash" value={shortHash(action.policyHash, 16)} mono />
            <Fact label="Reason" value={String(policy?.reasonCode ?? "—")} />
          </div>
        </Card>
        <Card>
          <h2 style={{ margin: 0, fontSize: 18 }}>Credential & outcome</h2>
          <div className="tf-grid tf-grid-3" style={{ marginTop: 14 }}>
            <Fact label="Issuer" value={denied ? "—" : String(credential?.issuer ?? action.credentialIssuer ?? "—")} />
            <Fact label="Type" value={denied ? "—" : String(credential?.credentialType ?? "—")} />
            <Fact label="TTL" value={!denied && credential?.ttlSeconds ? `${credential.ttlSeconds}s` : "—"} />
            <Fact label="Single use" value={!denied && credential ? (credential.singleUse ? "yes" : "no") : "—"} />
            <Fact label="Outcome source" value={outcomeSource} />
            <Fact label="Completed" value={outcomeRef?.completedAt ? formatDate(outcomeRef.completedAt) : "—"} />
            <Fact label="Result hash" value={shortHash(outcomeRef?.resultHash ?? call?.resultHash, 16)} mono />
            <Fact label="Error class" value={String(outcomeRef?.errorClass ?? "—")} />
            <Fact label="Action id" value={shortHash(action.actionId, 16)} mono />
          </div>
        </Card>
      </div>

      <div className="tf-grid" style={{ marginTop: 18, gridTemplateColumns: "1fr 1fr" }}>
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

function GraphNode({ label, value }: { label: string; value: string }) {
  return (
    <div className="tf-graph-node">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function GraphArrow() {
  return <span className="tf-graph-arrow">→</span>;
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
