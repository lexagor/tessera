import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";

import { api } from "../api";
import { Badge, Card, formatDate, shortHash } from "@tessera/ui";
import { ReviewerReport } from "../components/Evidence";
import { readinessTone, type SharedEvidencePack } from "../lib/evidence";

export function PublicEvidencePage() {
  const { token = "" } = useParams();
  const query = useQuery({
    queryKey: ["public-evidence", token],
    queryFn: () => api<SharedEvidencePack>(`/v1/public/evidence/${encodeURIComponent(token)}`),
    retry: false,
  });

  if (query.isLoading) {
    return <div className="tf-public-shell"><Card>Loading evidence pack…</Card></div>;
  }
  if (query.isError || !query.data) {
    return (
      <div className="tf-public-shell">
        <Card>
          <h1>Reviewer link unavailable</h1>
          <p className="tf-muted">This link is invalid, expired, or has been revoked by the workspace owner.</p>
        </Card>
      </div>
    );
  }

  const { pack, org, environment, downloadUrl, reportUrl, verifyUrl, securityContact } = query.data;
  const summary = pack.summary;

  return (
    <div className="tf-public-shell">
      <header className="tf-public-head">
        <div>
          <Link to="/" className="tf-brand">Tessera</Link>
          <span className="tf-muted">Reviewer evidence</span>
        </div>
        <div className="tf-actions">
          <Badge tone={readinessTone(summary.readiness.status)}>{summary.readiness.score}% coverage</Badge>
          <a className="tf-btn" href={reportUrl}>Download report</a>
          <a className="tf-btn" href={downloadUrl}>Download archive</a>
        </div>
      </header>
      <div className="tf-public-title">
        <div>
          <div className="tf-kpi-label">Shared by {org.name}</div>
          <h1>{environment.name} evidence pack</h1>
          <p className="tf-muted">
            {formatDate(summary.window.since)} to {formatDate(summary.window.until)} · shared until{" "}
            {formatDate(pack.shareExpiresAt)} · pack {shortHash(pack.id, 10)}
          </p>
        </div>
        <a className="tf-btn primary" href={verifyUrl} target="_blank" rel="noreferrer">Verify a record</a>
      </div>
      <Card className="tf-report-shell">
        <ReviewerReport summary={summary} pack={{ id: pack.id, createdAt: pack.createdAt, expiresAt: pack.expiresAt }} />
      </Card>
      <footer className="tf-public-foot">
        <span>Security questions: <a href={`mailto:${securityContact}`}>{securityContact}</a></span>
        <span>Verify the archive offline with <code>tessera-verify</code>.</span>
      </footer>
    </div>
  );
}
