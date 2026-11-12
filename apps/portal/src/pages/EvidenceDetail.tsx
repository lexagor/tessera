import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";

import { api } from "../api";
import {
  Badge,
  Button,
  Card,
  CopyButton,
  EmptyState,
  ErrorBanner,
  PageHeader,
  formatDate,
  shortHash,
} from "@tessera/ui";
import { ReviewerReport } from "../components/Evidence";
import {
  isEvidenceSummary,
  readinessTone,
  type EvidencePack,
  type EvidenceSummary,
} from "../lib/evidence";

interface PackDetail extends EvidencePack {
  summary: EvidenceSummary | Record<string, never>;
}

export function EvidenceDetailPage() {
  const { packId = "" } = useParams();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState<"reviewer" | "artifacts">("reviewer");
  const [error, setError] = useState<string | null>(null);
  const [shareUrl, setShareUrl] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ["evidence-pack", packId],
    queryFn: () => api<PackDetail>(`/v1/evidence-packs/${encodeURIComponent(packId)}`),
    enabled: Boolean(packId),
  });

  const share = useMutation({
    mutationFn: () =>
      api<{ url: string; expiresAt: string }>(
        `/v1/evidence-packs/${encodeURIComponent(packId)}/share`,
        { method: "POST", body: JSON.stringify({ expiresInDays: 30 }) },
      ),
    onSuccess: async (result) => {
      setError(null);
      setShareUrl(result.url);
      await queryClient.invalidateQueries({ queryKey: ["evidence-pack", packId] });
      await queryClient.invalidateQueries({ queryKey: ["evidence-packs"] });
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  const revoke = useMutation({
    mutationFn: () =>
      api(`/v1/evidence-packs/${encodeURIComponent(packId)}/share`, { method: "DELETE" }),
    onSuccess: async () => {
      setError(null);
      setShareUrl(null);
      await queryClient.invalidateQueries({ queryKey: ["evidence-pack", packId] });
      await queryClient.invalidateQueries({ queryKey: ["evidence-packs"] });
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  if (query.isLoading) return <Card>Loading evidence pack…</Card>;
  if (query.isError || !query.data) {
    return <ErrorBanner message={query.error instanceof Error ? query.error.message : "Evidence pack not found"} />;
  }

  const pack = query.data;
  const summary = isEvidenceSummary(pack.summary) ? pack.summary : null;

  return (
    <>
      <PageHeader
        title="Evidence pack"
        subtitle={summary ? `${summary.orgName} · ${summary.environmentName} · ${formatDate(summary.window.since)} to ${formatDate(summary.window.until)}` : "Legacy evidence pack"}
        actions={
          <>
            <Link className="tf-btn ghost" to="/evidence">Back to evidence</Link>
            {pack.status === "ready" ? <a className="tf-btn" href={pack.downloadUrl}>Download archive</a> : null}
            {summary ? <a className="tf-btn" href={pack.reportUrl}>Download report</a> : null}
            {summary ? (
              <Button variant="primary" onClick={() => share.mutate()} disabled={share.isPending}>
                {share.isPending ? "Creating…" : pack.hasShare ? "Rotate reviewer link" : "Create reviewer link"}
              </Button>
            ) : null}
            {summary && pack.hasShare ? (
              <Button variant="danger" onClick={() => revoke.mutate()} disabled={revoke.isPending}>
                {revoke.isPending ? "Revoking…" : "Revoke link"}
              </Button>
            ) : null}
          </>
        }
      />
      <ErrorBanner message={error} />

      <div className="tf-pack-meta-row">
        <Card>
          <div className="tf-kpi-label">Pack</div>
          <div className="tf-mono" style={{ marginTop: 6 }}>{shortHash(pack.id, 16)}</div>
          <div className="tf-muted">{formatDate(pack.created_at)}</div>
        </Card>
        <Card>
          <div className="tf-kpi-label">Status</div>
          <div style={{ marginTop: 6 }}><Badge tone={pack.status === "ready" ? "ok" : pack.status === "failed" ? "bad" : "warn"}>{pack.status}</Badge></div>
          <div className="tf-muted">{pack.expires_at ? `expires ${formatDate(pack.expires_at)}` : "no expiry"}</div>
        </Card>
        <Card>
          <div className="tf-kpi-label">Readiness</div>
          <div style={{ marginTop: 6 }}>{summary ? <Badge tone={readinessTone(summary.readiness.status)}>{summary.readiness.score}%</Badge> : <Badge tone="muted">not recorded</Badge>}</div>
          <div className="tf-muted">{summary ? `${summary.readiness.covered} covered · ${summary.readiness.partial} partial · ${summary.readiness.gap} gap` : "Rebuild this pack for a reviewer report."}</div>
        </Card>
        <Card>
          <div className="tf-kpi-label">Reviewer access</div>
          <div style={{ marginTop: 6 }}>{pack.hasShare ? <Badge tone="ok">link active</Badge> : <Badge tone="muted">private</Badge>}</div>
          <div className="tf-muted">{pack.hasShare && pack.share_expires_at ? `expires ${formatDate(pack.share_expires_at)}` : "No external access"}</div>
        </Card>
      </div>

      {shareUrl ? (
        <Card className="tf-share-card">
          <div>
            <div className="tf-kpi-label">Reviewer link</div>
            <p className="tf-muted" style={{ margin: "4px 0 8px" }}>Anyone with this link can read the report and download the archive until it expires. Rotate it if it leaks.</p>
            <CopyRowInline value={shareUrl} />
          </div>
        </Card>
      ) : null}

      {!summary ? (
        <Card>
          <EmptyState title="This pack predates reviewer reports" action={<Link className="tf-btn primary" to="/evidence">Build a new pack</Link>}>
            The archive is still downloadable, but rebuild the pack to include control coverage,
            reviewer view, and the signed report.
          </EmptyState>
        </Card>
      ) : (
        <>
          <div className="tf-evidence-tabs" role="tablist" aria-label="Evidence pack views">
            <button className={`tf-saved-view ${tab === "reviewer" ? "active" : ""}`} onClick={() => setTab("reviewer")} role="tab" aria-selected={tab === "reviewer"}>Reviewer view</button>
            <button className={`tf-saved-view ${tab === "artifacts" ? "active" : ""}`} onClick={() => setTab("artifacts")} role="tab" aria-selected={tab === "artifacts"}>Artifacts</button>
          </div>
          {tab === "reviewer" ? (
            <Card className="tf-report-shell">
              <ReviewerReport summary={summary} pack={{ id: pack.id, createdAt: pack.created_at, expiresAt: pack.expires_at }} linkActions />
            </Card>
          ) : (
            <ArtifactView summary={summary} pack={pack} />
          )}
        </>
      )}
    </>
  );
}

function ArtifactView({ summary, pack }: { summary: EvidenceSummary; pack: EvidencePack }) {
  return (
    <div className="tf-evidence-bottom-grid">
      <Card>
        <div className="tf-kpi-label">Archive contents</div>
        <h2 style={{ margin: "6px 0 12px", fontSize: 18 }}>Signed artifacts</h2>
        <div className="tf-proof-rows">
          <ArtifactRow label="Action records" value={summary.records.length} note={`${summary.inventory.verified} verified`} />
          <ArtifactRow label="Policy versions" value={summary.policies.length} note={summary.policies.map((policy) => `${policy.id} v${policy.version}`).join(", ") || "none"} />
          <ArtifactRow label="Authority transitions" value={summary.transitions.length} note="signed and hash-linked" />
          <ArtifactRow label="Active agent keys" value={summary.inventory.agentKeys} note="environment-scoped" />
          <ArtifactRow label="Review decisions" value={summary.reviews.total} note={`${summary.reviews.pending} pending`} />
          <ArtifactRow label="Verification links" value={summary.verificationLinks.length} note={`${summary.inventory.verificationLinks} active`} />
          <ArtifactRow label="Anchor batches" value={summary.proof.anchors} note={summary.proof.anchors ? "on-chain" : "not anchored"} />
        </div>
      </Card>
      <Card>
        <div className="tf-kpi-label">Pack scope</div>
        <h2 style={{ margin: "6px 0 12px", fontSize: 18 }}>Included evidence</h2>
        <div className="tf-proof-rows">
          <ArtifactRow label="Environment" value={summary.environmentName} />
          <ArtifactRow label="Scope" value={summary.scope.type === "agent" ? `Agent ${summary.scope.agentId}` : "All agents"} />
          <ArtifactRow label="Window" value={`${formatDate(summary.window.since)} – ${formatDate(summary.window.until)}`} />
          <ArtifactRow label="Frameworks" value={summary.frameworks.map((framework) => framework.name).join(", ")} />
          <ArtifactRow label="Recipients" value={summary.recipients.join(", ") || "Internal"} />
          <ArtifactRow label="Download" value={<a href={pack.downloadUrl}>Signed archive</a>} />
        </div>
      </Card>
    </div>
  );
}

function ArtifactRow({ label, value, note }: { label: string; value: React.ReactNode; note?: string }) {
  return (
    <div className="tf-artifact-row">
      <div>
        <span>{label}</span>
        {note ? <div className="tf-muted">{note}</div> : null}
      </div>
      <strong>{value}</strong>
    </div>
  );
}

function CopyRowInline({ value }: { value: string }) {
  return (
    <div className="tf-copy-row">
      <code className="tf-code">{value}</code>
      <CopyButton value={value} />
    </div>
  );
}
