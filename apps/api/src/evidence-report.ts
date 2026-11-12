import type { EvidencePackSummary } from "./evidence.js";

function escapeHtml(value: unknown): string {
  return String(value ?? "").replace(/[&<>"']/g, (character) => {
    switch (character) {
      case "&":
        return "&amp;";
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case '"':
        return "&quot;";
      default:
        return "&#39;";
    }
  });
}

function date(value: string | null | undefined): string {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? escapeHtml(value) : parsed.toISOString().replace("T", " ").replace(".000Z", " UTC");
}

function statusLabel(status: string): string {
  return status === "covered" ? "Covered" : status === "partial" ? "Partial" : "Gap";
}

function rows(summary: EvidencePackSummary): string {
  if (!summary.records.length) {
    return `<tr><td colspan="6" class="muted">No action records in this window.</td></tr>`;
  }
  return summary.records
    .slice(0, 100)
    .map(
      (record) => `<tr>
        <td class="mono">${escapeHtml(record.actionId)}</td>
        <td>${escapeHtml(record.agentId)}</td>
        <td>${escapeHtml(record.tool)}</td>
        <td>${escapeHtml(record.decision)}</td>
        <td>${escapeHtml(record.outcomeStatus ?? "pending")}${record.outcomeSource ? ` <span class="muted">(${escapeHtml(record.outcomeSource)})</span>` : ""}</td>
        <td class="mono">${escapeHtml(record.receiptId.slice(0, 18))}…</td>
      </tr>`,
    )
    .join("");
}

function frameworks(summary: EvidencePackSummary): string {
  return summary.frameworks
    .map(
      (framework) => `<section class="framework">
        <div class="framework-head">
          <div><h3>${escapeHtml(framework.name)}</h3><p class="muted">${escapeHtml(framework.description)}</p></div>
          <span class="score">${framework.readiness}%</span>
        </div>
        <table>
          <thead><tr><th>Control</th><th>Question</th><th>Status</th><th>Evidence</th></tr></thead>
          <tbody>
            ${framework.controls
              .map(
                (control) => `<tr>
                  <td><strong>${escapeHtml(control.id)}</strong><br /><span class="muted">${escapeHtml(control.title)}</span></td>
                  <td>${escapeHtml(control.question)}</td>
                  <td><span class="status ${control.status}">${statusLabel(control.status)}</span></td>
                  <td class="muted">${escapeHtml(control.detail)}</td>
                </tr>`,
              )
              .join("")}
          </tbody>
        </table>
      </section>`,
    )
    .join("");
}

function policies(summary: EvidencePackSummary): string {
  if (!summary.policies.length) return `<p class="muted">No policy versions included.</p>`;
  return `<table><thead><tr><th>Policy</th><th>Version</th><th>Rules</th></tr></thead><tbody>
    ${summary.policies
      .map(
        (policy) => `<tr><td><strong>${escapeHtml(policy.name)}</strong><br /><span class="muted mono">${escapeHtml(policy.id)}</span></td><td>${policy.version}</td><td>${policy.grants
          .map((grant: any) => `<span class="mono">${escapeHtml(grant.resource ?? "rule")}</span>`)
          .join("<br />")}</td></tr>`,
      )
      .join("")}
  </tbody></table>`;
}

function transitions(summary: EvidencePackSummary): string {
  if (!summary.transitions.length) return `<p class="muted">No authority transitions in this window.</p>`;
  return `<table><thead><tr><th>Transition</th><th>Target</th><th>When</th><th>Event hash</th></tr></thead><tbody>
    ${summary.transitions
      .map(
        (transition) => `<tr><td>${escapeHtml(transition.kind)}</td><td>${escapeHtml(transition.target)}</td><td>${date(transition.at)}</td><td class="mono">${escapeHtml(transition.eventHash.slice(0, 22))}…</td></tr>`,
      )
      .join("")}
  </tbody></table>`;
}

function reviews(summary: EvidencePackSummary): string {
  return `<div class="stats">
    <div><strong>${summary.reviews.total}</strong><span>total</span></div>
    <div><strong>${summary.reviews.approved}</strong><span>approved</span></div>
    <div><strong>${summary.reviews.rejected}</strong><span>rejected</span></div>
    <div><strong>${summary.reviews.pending}</strong><span>pending</span></div>
  </div>`;
}

export function renderEvidenceReport(
  summary: EvidencePackSummary,
  pack: { id: string; createdAt: string; expiresAt?: string | null },
): string {
  const recipientLine = summary.recipients.length
    ? `Recipients: ${summary.recipients.join(", ")}`
    : "Internal evidence pack";
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Evidence pack · ${escapeHtml(summary.orgName)}</title>
<style>
  :root { color-scheme: light; --ink: #111; --muted: #666; --line: #ddd; --soft: #f6f6f4; --accent: #3451b2; --ok: #137a4b; --warn: #8a5a00; --bad: #a52222; }
  * { box-sizing: border-box; }
  body { margin: 0; background: #f0f0ed; color: var(--ink); font: 14px/1.55 ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
  .page { max-width: 1040px; margin: 36px auto; background: #fff; border: 1px solid var(--line); padding: 46px; box-shadow: 0 12px 36px rgba(0,0,0,.06); }
  h1, h2, h3 { margin: 0; line-height: 1.15; }
  h1 { font-size: 34px; letter-spacing: -.03em; }
  h2 { font-size: 20px; margin: 34px 0 12px; border-bottom: 1px solid var(--line); padding-bottom: 8px; }
  h3 { font-size: 16px; }
  p { margin: 6px 0; }
  .eyebrow { text-transform: uppercase; letter-spacing: .12em; font-size: 11px; color: var(--muted); }
  .top { display: flex; justify-content: space-between; gap: 28px; border-bottom: 2px solid var(--ink); padding-bottom: 24px; }
  .top p { color: var(--muted); }
  .scorebox { min-width: 160px; text-align: right; }
  .scorebox strong { display: block; font-size: 44px; letter-spacing: -.05em; }
  .scorebox span { color: var(--muted); }
  .muted { color: var(--muted); }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11px; }
  table { width: 100%; border-collapse: collapse; margin: 8px 0 18px; font-size: 12px; }
  th { text-align: left; font-size: 10px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); border-bottom: 1px solid var(--line); padding: 8px; }
  td { border-bottom: 1px solid var(--line); padding: 9px 8px; vertical-align: top; }
  tr:last-child td { border-bottom: 0; }
  .status { display: inline-block; padding: 2px 7px; border-radius: 99px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: .04em; }
  .status.covered { color: var(--ok); background: #e8f6ef; }
  .status.partial { color: var(--warn); background: #fff5dc; }
  .status.gap { color: var(--bad); background: #fdecec; }
  .stats { display: flex; gap: 10px; flex-wrap: wrap; }
  .stats div { border: 1px solid var(--line); padding: 10px 16px; min-width: 110px; }
  .stats strong { display: block; font-size: 22px; }
  .stats span { color: var(--muted); font-size: 11px; }
  .framework { border: 1px solid var(--line); padding: 16px; margin: 12px 0; }
  .framework-head { display: flex; justify-content: space-between; gap: 16px; align-items: flex-start; }
  .framework-head .score { font-size: 20px; font-weight: 700; }
  .framework p { color: var(--muted); font-size: 12px; }
  .gaps li { margin: 4px 0; }
  .note { background: var(--soft); border-left: 3px solid var(--accent); padding: 12px 14px; margin: 10px 0; font-size: 12px; }
  .footer { margin-top: 36px; border-top: 1px solid var(--line); padding-top: 16px; color: var(--muted); font-size: 11px; }
  @media print { body { background: #fff; } .page { margin: 0; border: 0; box-shadow: none; padding: 0; } h2 { break-after: avoid; } tr { break-inside: avoid; } }
</style>
</head>
<body>
<main class="page">
  <div class="eyebrow">Tessera · Evidence pack</div>
  <div class="top">
    <div>
      <h1>${escapeHtml(summary.orgName)}</h1>
      <p>${escapeHtml(summary.environmentName)} environment · ${summary.scope.type === "agent" ? `agent ${escapeHtml(summary.scope.agentId ?? "")}` : "all agents"}</p>
      <p>Window ${date(summary.window.since)} → ${date(summary.window.until)}</p>
      <p>${escapeHtml(recipientLine)}</p>
    </div>
    <div class="scorebox">
      <strong>${summary.readiness.score}%</strong>
      <span>evidence coverage</span>
      <p class="mono">${escapeHtml(pack.id)}</p>
    </div>
  </div>

  <h2>Reviewer summary</h2>
  <p>${escapeHtml(summary.readiness.explanation)}</p>
  <div class="stats">
    <div><strong>${summary.inventory.actions}</strong><span>action records</span></div>
    <div><strong>${summary.inventory.verified}</strong><span>verified</span></div>
    <div><strong>${summary.inventory.denied}</strong><span>blocked</span></div>
    <div><strong>${summary.inventory.transitions}</strong><span>transitions</span></div>
    <div><strong>${summary.inventory.reviews}</strong><span>reviews</span></div>
  </div>
  ${summary.gaps.length ? `<div class="note"><strong>Open gaps</strong><ul class="gaps">${summary.gaps.map((gap) => `<li>${escapeHtml(gap)}</li>`).join("")}</ul></div>` : ""}
  ${summary.delta ? `<div class="note"><strong>Changes since the previous pack</strong><div class="stats">
    <div><strong>+${summary.delta.actions}</strong><span>actions</span></div>
    <div><strong>+${summary.delta.denied}</strong><span>blocked</span></div>
    <div><strong>+${summary.delta.reviews}</strong><span>review decisions</span></div>
    <div><strong>+${summary.delta.transitions}</strong><span>transitions</span></div>
    <div><strong>+${summary.delta.policyChanges}</strong><span>policy changes</span></div>
  </div></div>` : ""}

  <h2>Control coverage</h2>
  ${frameworks(summary)}

  <h2>Actions included</h2>
  <p class="muted">${summary.records.length} record(s) in the export${summary.records.length > 100 ? "; the table previews the newest 100." : "."}</p>
  <table>
    <thead><tr><th>Action</th><th>Agent</th><th>Tool</th><th>Decision</th><th>Outcome</th><th>Receipt</th></tr></thead>
    <tbody>${rows(summary)}</tbody>
  </table>

  <h2>Policy versions</h2>
  ${policies(summary)}

  <h2>Human review</h2>
  ${reviews(summary)}

  <h2>Authority transitions</h2>
  ${transitions(summary)}

  <h2>Verification links</h2>
  ${summary.verificationLinks.length ? `<table><thead><tr><th>Action</th><th>Created</th><th>Expires</th></tr></thead><tbody>
    ${summary.verificationLinks
      .map(
        (link) => `<tr><td class="mono">${escapeHtml(link.actionId)}</td><td>${date(link.createdAt)}</td><td>${date(link.expiresAt)}</td></tr>`,
      )
      .join("")}
  </tbody></table>` : `<p class="muted">No active verification links in this window.</p>`}

  <h2>Proof and retention</h2>
  <table>
    <tbody>
      <tr><td>Chain verification</td><td>${summary.proof.chainsVerified === null ? "not checked" : summary.proof.chainsVerified ? "verified" : "failed"}</td></tr>
      <tr><td>Key-event ledger</td><td>${summary.proof.keyEventsVerified === null ? "not checked" : summary.proof.keyEventsVerified ? "verified" : "failed"}</td></tr>
      <tr><td>Receipts in broker chains</td><td>${summary.proof.chainReceipts}</td></tr>
      <tr><td>Anchor batches</td><td>${summary.proof.anchors}${summary.proof.anchorLatest ? ` · latest ${escapeHtml(summary.proof.anchorLatest)}` : ""}</td></tr>
      <tr><td>Verification links</td><td>${summary.inventory.verificationLinks} active</td></tr>
      <tr><td>Pack created</td><td>${date(pack.createdAt)}${pack.expiresAt ? ` · expires ${date(pack.expiresAt)}` : ""}</td></tr>
    </tbody>
  </table>

  <h2>What this pack does not prove</h2>
  <ul class="gaps">${summary.notes.map((note) => `<li>${escapeHtml(note)}</li>`).join("")}</ul>

  <div class="footer">
    Tessera evidence report · generated ${date(summary.generatedAt)} · Verify the downloaded archive with
    <span class="mono">tessera-verify</span>. This report is an evidence artifact, not a certification.
  </div>
</main>
</body>
</html>`;
}
