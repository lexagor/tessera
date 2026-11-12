import { Link } from "react-router-dom";

import { Badge, Card, formatDate, shortHash } from "@tessera/ui";
import {
  coverageLabel,
  readinessTone,
  type CoverageStatus,
  type EvidenceFramework,
  type EvidenceSummary,
} from "../lib/evidence";

export function ReadinessRing({ score, size = 132 }: { score: number; size?: number }) {
  return (
    <div
      className="tf-readiness-ring"
      style={{
        width: size,
        height: size,
        background: `conic-gradient(var(--tf-accent) ${Math.max(0, Math.min(100, score)) * 3.6}deg, var(--tf-line) 0deg)`,
      }}
      aria-label={`${score}% evidence coverage`}
    >
      <div className="tf-readiness-ring-inner">
        <strong>{score}%</strong>
        <span>coverage</span>
      </div>
    </div>
  );
}

export function StatusBadge({ status }: { status: CoverageStatus }) {
  return <Badge tone={status === "covered" ? "ok" : status === "partial" ? "warn" : "bad"}>{coverageLabel(status)}</Badge>;
}

export function ReadinessCard({ summary }: { summary: EvidenceSummary }) {
  return (
    <Card className="tf-evidence-hero">
      <div className="tf-evidence-hero-main">
        <div>
          <div className="tf-kpi-label">Evidence readiness</div>
          <div className="tf-evidence-scoreline">
            <h2>{summary.readiness.score}%</h2>
            <Badge tone={readinessTone(summary.readiness.status)}>
              {summary.readiness.status === "ready" ? "Review ready" : summary.readiness.status === "partial" ? "Gaps to close" : "Needs evidence"}
            </Badge>
          </div>
          <p>{summary.readiness.explanation}</p>
          <div className="tf-evidence-meta">
            <span>{summary.readiness.covered} covered</span>
            <span>{summary.readiness.partial} partial</span>
            <span>{summary.readiness.gap} control gaps</span>
            <span>{summary.gaps.length} open items</span>
            <span>{summary.readiness.controls} mapped controls</span>
          </div>
        </div>
        <ReadinessRing score={summary.readiness.score} />
      </div>
      <div className="tf-evidence-stats">
        <div><strong>{summary.inventory.actions}</strong><span>actions</span></div>
        <div><strong>{summary.inventory.verified}</strong><span>verified</span></div>
        <div><strong>{summary.inventory.denied}</strong><span>blocked</span></div>
        <div><strong>{summary.inventory.transitions}</strong><span>transitions</span></div>
        <div><strong>{summary.inventory.reviews}</strong><span>reviews</span></div>
        <div><strong>{summary.inventory.evidencePacks}</strong><span>packs</span></div>
      </div>
    </Card>
  );
}

export function DeltaCard({ summary }: { summary: EvidenceSummary }) {
  if (!summary.delta) {
    return (
      <Card>
        <div className="tf-kpi-label">What changed</div>
        <h2 style={{ margin: "6px 0 4px", fontSize: 18 }}>First review cycle</h2>
        <p className="tf-muted" style={{ margin: 0 }}>
          Build another pack later to compare new actions, reviews, policy changes, and transitions
          since this snapshot.
        </p>
      </Card>
    );
  }
  const delta = summary.delta;
  return (
    <Card>
      <div className="tf-actions" style={{ justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <div className="tf-kpi-label">Since the last pack</div>
          <h2 style={{ margin: "6px 0 4px", fontSize: 18 }}>{formatDate(delta.sincePackAt)}</h2>
        </div>
        <Link className="tf-btn ghost" to={`/evidence/${delta.sincePackId}`}>Open previous</Link>
      </div>
      <div className="tf-delta-grid">
        <div><strong>+{delta.actions}</strong><span>actions</span></div>
        <div><strong>+{delta.denied}</strong><span>blocked</span></div>
        <div><strong>+{delta.reviews}</strong><span>review decisions</span></div>
        <div><strong>+{delta.transitions}</strong><span>transitions</span></div>
        <div><strong>+{delta.policyChanges}</strong><span>policy changes</span></div>
      </div>
    </Card>
  );
}

export function FrameworkGrid({ frameworks }: { frameworks: EvidenceFramework[] }) {
  return (
    <div className="tf-framework-grid">
      {frameworks.map((framework) => (
        <Card className="tf-framework-card" key={framework.id}>
          <div className="tf-framework-head">
            <div>
              <h2>{framework.name}</h2>
              <p className="tf-muted">{framework.description}</p>
            </div>
            <div className="tf-framework-score">
              <strong>{framework.readiness}%</strong>
              <span>
                {framework.covered}/{framework.controls.length} covered
                {framework.partial ? ` · ${framework.partial} partial` : ""}
              </span>
            </div>
          </div>
          <div className="tf-framework-controls">
            {framework.controls.map((control) => (
              <div className="tf-control-row" key={`${framework.id}-${control.id}`}>
                <div>
                  <strong>{control.id}</strong>
                  <span>{control.title}</span>
                </div>
                <StatusBadge status={control.status} />
              </div>
            ))}
          </div>
          {framework.gap > 0 ? (
            <div className="tf-framework-gap">{framework.gap} control(s) still need direct evidence.</div>
          ) : null}
        </Card>
      ))}
    </div>
  );
}

export function GapList({ summary }: { summary: EvidenceSummary }) {
  return (
    <Card>
      <div className="tf-actions" style={{ justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <div className="tf-kpi-label">Gaps to close</div>
          <h2 style={{ margin: "6px 0 4px", fontSize: 18 }}>What a reviewer will ask about</h2>
        </div>
        <Badge tone={summary.gaps.length ? "warn" : "ok"}>{summary.gaps.length ? `${summary.gaps.length} open` : "No gaps"}</Badge>
      </div>
      {summary.gaps.length ? (
        <ul className="tf-gap-list">
          {summary.gaps.map((gap, index) => <li key={index}>{gap}</li>)}
        </ul>
      ) : (
        <p className="tf-muted" style={{ margin: "10px 0 0" }}>Every selected control has direct evidence in this window.</p>
      )}
    </Card>
  );
}

export function ProofHealth({ summary }: { summary: EvidenceSummary }) {
  return (
    <Card>
      <div className="tf-kpi-label">Proof health</div>
      <h2 style={{ margin: "6px 0 10px", fontSize: 18 }}>Chain and ledger</h2>
      <div className="tf-proof-rows">
        <ProofRow label="Chains" value={summary.proof.chainsVerified === null ? "not checked" : summary.proof.chainsVerified ? "verified" : "failed"} tone={summary.proof.chainsVerified === false ? "bad" : "ok"} />
        <ProofRow label="Key-event ledger" value={summary.proof.keyEventsVerified === null ? "not checked" : summary.proof.keyEventsVerified ? "verified" : "failed"} tone={summary.proof.keyEventsVerified === false ? "bad" : "ok"} />
        <ProofRow label="Receipts" value={String(summary.proof.chainReceipts)} />
        <ProofRow label="Anchors" value={summary.proof.anchors ? String(summary.proof.anchors) : `${summary.proof.unanchoredAgents} unanchored`} tone={summary.proof.anchors ? "ok" : "warn"} />
        <ProofRow label="Verification links" value={String(summary.inventory.verificationLinks)} />
      </div>
    </Card>
  );
}

function ProofRow({ label, value, tone }: { label: string; value: string; tone?: "ok" | "warn" | "bad" }) {
  return (
    <div className="tf-proof-row">
      <span>{label}</span>
      <Badge tone={tone ?? "muted"}>{value}</Badge>
    </div>
  );
}

export function ReviewerReport({
  summary,
  pack,
  linkActions = false,
}: {
  summary: EvidenceSummary;
  pack?: { id: string; createdAt: string; expiresAt?: string | null };
  linkActions?: boolean;
}) {
  return (
    <div className="tf-report">
      <header className="tf-report-head">
        <div>
          <div className="tf-kpi-label">Reviewer report</div>
          <h2>{summary.orgName}</h2>
          <p>
            {summary.environmentName} · {summary.scope.type === "agent" ? `agent ${summary.scope.agentId}` : "all agents"} ·{" "}
            {formatDate(summary.window.since)} to {formatDate(summary.window.until)}
          </p>
          {summary.recipients.length ? <p>Prepared for {summary.recipients.join(", ")}</p> : null}
        </div>
        <div className="tf-report-score">
          <strong>{summary.readiness.score}%</strong>
          <span>evidence coverage</span>
          {pack ? <code>{shortHash(pack.id, 12)}</code> : null}
        </div>
      </header>

      <section className="tf-report-section">
        <h3>Reviewer summary</h3>
        <p>{summary.readiness.explanation}</p>
        <div className="tf-report-stats">
          <div><strong>{summary.inventory.actions}</strong><span>action records</span></div>
          <div><strong>{summary.inventory.verified}</strong><span>verified</span></div>
          <div><strong>{summary.inventory.denied}</strong><span>blocked</span></div>
          <div><strong>{summary.inventory.transitions}</strong><span>transitions</span></div>
          <div><strong>{summary.inventory.reviews}</strong><span>reviews</span></div>
        </div>
        {summary.gaps.length ? (
          <div className="tf-report-note">
            <strong>Open gaps</strong>
            <ul>{summary.gaps.map((gap, index) => <li key={index}>{gap}</li>)}</ul>
          </div>
        ) : null}
        {summary.delta ? (
          <div className="tf-report-note">
            <strong>Changes since the previous pack</strong>
            <div className="tf-delta-grid">
              <div><strong>+{summary.delta.actions}</strong><span>actions</span></div>
              <div><strong>+{summary.delta.denied}</strong><span>blocked</span></div>
              <div><strong>+{summary.delta.reviews}</strong><span>review decisions</span></div>
              <div><strong>+{summary.delta.transitions}</strong><span>transitions</span></div>
              <div><strong>+{summary.delta.policyChanges}</strong><span>policy changes</span></div>
            </div>
          </div>
        ) : null}
      </section>

      <section className="tf-report-section">
        <h3>Control coverage</h3>
        {summary.frameworks.map((framework) => (
          <div className="tf-report-framework" key={framework.id}>
            <div className="tf-report-framework-head">
              <div>
                <strong>{framework.name}</strong>
                <p>{framework.description}</p>
              </div>
              <span>{framework.readiness}%</span>
            </div>
            <table className="tf-table">
              <thead><tr><th>Control</th><th>Question</th><th>Status</th><th>Evidence</th></tr></thead>
              <tbody>
                {framework.controls.map((control) => (
                  <tr key={control.id}>
                    <td><strong>{control.id}</strong><div className="tf-muted">{control.title}</div></td>
                    <td>{control.question}</td>
                    <td><StatusBadge status={control.status} /></td>
                    <td className="tf-muted">{control.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}
      </section>

      <section className="tf-report-section">
        <h3>Actions included</h3>
        <p className="tf-muted">{summary.records.length} record(s) in the export{summary.records.length > 100 ? "; this table previews the newest 100." : "."}</p>
        <div className="tf-report-table-wrap">
          <table className="tf-table">
            <thead><tr><th>Action</th><th>Agent</th><th>Tool</th><th>Decision</th><th>Outcome</th><th>Receipt</th></tr></thead>
            <tbody>
              {summary.records.slice(0, 100).map((record) => (
                <tr key={record.actionId}>
                  <td className="tf-mono">
                    {linkActions ? <Link to={`/actions/${record.actionId}`}>{shortHash(record.actionId, 10)}</Link> : shortHash(record.actionId, 10)}
                  </td>
                  <td>{record.agentId}</td>
                  <td>{record.tool}</td>
                  <td><Badge tone={record.decision === "allow" ? "ok" : "bad"}>{record.decision}</Badge></td>
                  <td>{record.outcomeStatus ?? "pending"}{record.outcomeSource ? <div className="tf-muted">{record.outcomeSource}</div> : null}</td>
                  <td className="tf-mono">{shortHash(record.receiptId, 10)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <div className="tf-report-columns">
        <section className="tf-report-section">
          <h3>Policy versions</h3>
          {summary.policies.length ? summary.policies.map((policy) => (
            <div className="tf-report-policy" key={policy.id}>
              <strong>{policy.name}</strong>
              <span className="tf-muted">{policy.id} · v{policy.version}</span>
              <div className="tf-muted">{policy.grants.length} rule(s)</div>
            </div>
          )) : <p className="tf-muted">No policy versions included.</p>}
        </section>
        <section className="tf-report-section">
          <h3>Human review</h3>
          <div className="tf-report-stats">
            <div><strong>{summary.reviews.total}</strong><span>total</span></div>
            <div><strong>{summary.reviews.approved}</strong><span>approved</span></div>
            <div><strong>{summary.reviews.rejected}</strong><span>rejected</span></div>
            <div><strong>{summary.reviews.pending}</strong><span>pending</span></div>
          </div>
        </section>
      </div>

      <section className="tf-report-section">
        <h3>Authority transitions</h3>
        {summary.transitions.length ? (
          <table className="tf-table">
            <thead><tr><th>Transition</th><th>Target</th><th>When</th><th>Event hash</th></tr></thead>
            <tbody>
              {summary.transitions.map((transition) => (
                <tr key={transition.id}>
                  <td>{transition.kind}</td>
                  <td>{transition.target}</td>
                  <td>{formatDate(transition.at)}</td>
                  <td className="tf-mono">{shortHash(transition.eventHash, 12)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : <p className="tf-muted">No authority transitions in this window.</p>}
      </section>

      <section className="tf-report-section">
        <h3>Verification links</h3>
        {summary.verificationLinks.length ? (
          <table className="tf-table">
            <thead><tr><th>Action</th><th>Created</th><th>Expires</th></tr></thead>
            <tbody>
              {summary.verificationLinks.map((link) => (
                <tr key={link.id}>
                  <td className="tf-mono">{shortHash(link.actionId, 12)}</td>
                  <td>{formatDate(link.createdAt)}</td>
                  <td>{formatDate(link.expiresAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : <p className="tf-muted">No active verification links in this window.</p>}
      </section>

      <section className="tf-report-section">
        <h3>Proof and retention</h3>
        <div className="tf-proof-rows">
          <ProofRow label="Chain verification" value={summary.proof.chainsVerified === null ? "not checked" : summary.proof.chainsVerified ? "verified" : "failed"} tone={summary.proof.chainsVerified === false ? "bad" : "ok"} />
          <ProofRow label="Key-event ledger" value={summary.proof.keyEventsVerified === null ? "not checked" : summary.proof.keyEventsVerified ? "verified" : "failed"} tone={summary.proof.keyEventsVerified === false ? "bad" : "ok"} />
          <ProofRow label="Receipts in broker chains" value={String(summary.proof.chainReceipts)} />
          <ProofRow label="Anchor batches" value={String(summary.proof.anchors)} tone={summary.proof.anchors ? "ok" : "warn"} />
          <ProofRow label="Active verification links" value={String(summary.inventory.verificationLinks)} />
          {pack ? <ProofRow label="Pack created" value={formatDate(pack.createdAt)} /> : null}
          {pack?.expiresAt ? <ProofRow label="Pack expires" value={formatDate(pack.expiresAt)} /> : null}
        </div>
      </section>

      <section className="tf-report-section">
        <h3>What this pack does not prove</h3>
        <ul className="tf-gap-list">{summary.notes.map((note, index) => <li key={index}>{note}</li>)}</ul>
      </section>

      <footer className="tf-report-foot">
        Generated {formatDate(summary.generatedAt)} · Verify the downloaded archive with <code>tessera-verify</code>. This report is an evidence artifact, not a certification.
      </footer>
    </div>
  );
}
