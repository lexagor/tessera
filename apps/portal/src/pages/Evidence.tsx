import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";

import { api, environmentQuery } from "../api";
import { useWorkspace } from "../App";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorBanner,
  Modal,
  PageHeader,
  formatDate,
} from "@tessera/ui";
import {
  DeltaCard,
  FrameworkGrid,
  GapList,
  ProofHealth,
  ReadinessCard,
} from "../components/Evidence";
import {
  FRAMEWORK_OPTIONS,
  isEvidenceSummary,
  readinessTone,
  type EvidencePack,
  type EvidenceSummary,
} from "../lib/evidence";

function day(value: Date): string {
  return value.toISOString().slice(0, 10);
}

export function EvidencePage() {
  const { environmentId } = useWorkspace();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  const [showBuild, setShowBuild] = useState(false);
  const [frameworks, setFrameworks] = useState<string[]>(FRAMEWORK_OPTIONS.map((item) => item.id));
  const [since, setSince] = useState(() => day(new Date(Date.now() - 30 * 86_400_000)));
  const [until, setUntil] = useState(() => day(new Date()));
  const [recipients, setRecipients] = useState("");

  const readiness = useQuery({
    queryKey: ["evidence-readiness", environmentId],
    queryFn: () => api<EvidenceSummary>(`/v1/evidence/readiness${environmentQuery(environmentId)}`),
    enabled: Boolean(environmentId),
  });
  const packs = useQuery({
    queryKey: ["evidence-packs", environmentId],
    queryFn: () =>
      api<{ items: EvidencePack[] }>(`/v1/evidence-packs${environmentQuery(environmentId)}`),
    enabled: Boolean(environmentId),
  });
  const create = useMutation({
    mutationFn: () =>
      api<{ id: string }>(`/v1/evidence-packs${environmentQuery(environmentId)}`, {
        method: "POST",
        body: JSON.stringify({
          frameworks,
          since,
          until,
          recipients: recipients.split(",").map((item) => item.trim()).filter(Boolean),
        }),
      }),
    onSuccess: async (pack) => {
      setError(null);
      setShowBuild(false);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["evidence-packs"] }),
        queryClient.invalidateQueries({ queryKey: ["evidence-readiness"] }),
      ]);
      navigate(`/evidence/${pack.id}`);
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  const summary = readiness.data;
  const packItems = packs.data?.items ?? [];
  const latestDeltaSummary = useMemo(() => {
    for (const pack of packItems) {
      if (isEvidenceSummary(pack.summary) && pack.summary.delta) return pack.summary;
    }
    return summary;
  }, [packItems, summary]);

  function toggleFramework(id: string) {
    setFrameworks((current) =>
      current.includes(id) ? current.filter((item) => item !== id) : [...current, id],
    );
  }

  return (
    <>
      <PageHeader
        title="Evidence"
        subtitle="Answer a security reviewer with signed records, mapped controls, and a shareable pack."
        actions={
          <Button variant="primary" onClick={() => setShowBuild(true)} disabled={!environmentId}>
            Build evidence pack
          </Button>
        }
      />
      <ErrorBanner message={error} />
      {summary ? (
        <>
          <ReadinessCard summary={summary} />
          <div className="tf-evidence-top-grid">
            <DeltaCard summary={latestDeltaSummary ?? summary} />
            <ProofHealth summary={summary} />
          </div>
          <SectionTitle title="Framework coverage" note="Coverage is mapped evidence, not a certification." />
          <FrameworkGrid frameworks={summary.frameworks} />
          <div className="tf-evidence-bottom-grid">
            <GapList summary={summary} />
            <Card>
              <div className="tf-kpi-label">Pack checklist</div>
              <h2 style={{ margin: "6px 0 10px", fontSize: 18 }}>Ready for a reviewer</h2>
              <div className="tf-checklist">
                <ChecklistItem done={summary.inventory.actions > 0} label="Action records in the window" />
                <ChecklistItem done={summary.inventory.verified > 0} label="Broker signatures independently verified" />
                <ChecklistItem done={summary.inventory.reviews > 0} label="Human review trail present" />
                <ChecklistItem done={summary.inventory.transitions > 0} label="Signed authority transitions" />
                <ChecklistItem done={summary.inventory.verificationLinks > 0} label="Public verification link available" />
                <ChecklistItem done={summary.proof.anchors > 0} label="On-chain anchor batch" optional />
              </div>
            </Card>
          </div>
        </>
      ) : readiness.isLoading ? (
        <Card>Loading evidence posture…</Card>
      ) : (
        <Card>
          <EmptyState title="No evidence posture yet">
            Create an environment, instrument an action, then build the first evidence pack.
          </EmptyState>
        </Card>
      )}

      <SectionTitle title="Evidence packs" note="Each pack is a signed snapshot with a reviewer report." />
      <Card>
        {packItems.length ? (
          <table className="tf-table">
            <thead>
              <tr><th>Created</th><th>Window</th><th>Scope</th><th>Readiness</th><th>Reviewer link</th><th /></tr>
            </thead>
            <tbody>
              {packItems.map((pack) => {
                const report = isEvidenceSummary(pack.summary);
                return (
                  <tr key={pack.id}>
                    <td>{formatDate(pack.created_at)}</td>
                    <td className="tf-muted">
                      {report ? `${formatDate(pack.summary.window.since)} – ${formatDate(pack.summary.window.until)}` : "Legacy pack"}
                    </td>
                    <td>{report ? (pack.summary.scope.type === "agent" ? `Agent ${pack.summary.scope.agentId}` : "Environment") : "—"}</td>
                    <td>
                      {report ? (
                        <div className="tf-pack-readiness">
                          <Badge tone={readinessTone(pack.summary.readiness.status)}>{pack.summary.readiness.score}%</Badge>
                          <span>{pack.summary.readiness.covered} covered{pack.summary.readiness.partial ? ` · ${pack.summary.readiness.partial} partial` : ""}</span>
                        </div>
                      ) : <Badge tone="muted">rebuild</Badge>}
                    </td>
                    <td>{pack.hasShare ? <Badge tone="ok">shared</Badge> : <span className="tf-muted">not shared</span>}</td>
                    <td>
                      <div className="tf-actions" style={{ justifyContent: "flex-end" }}>
                        {report ? <Link className="tf-btn ghost" to={`/evidence/${pack.id}`}>Review</Link> : null}
                        {pack.status === "ready" ? <a className="tf-btn ghost" href={pack.downloadUrl}>Download</a> : null}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        ) : (
          <EmptyState title="No evidence packs yet" action={<Button variant="primary" onClick={() => setShowBuild(true)}>Build the first pack</Button>}>
            A pack contains the signed archive, policy versions, authority transitions, anchors, and a
            reviewer-ready report.
          </EmptyState>
        )}
      </Card>

      {showBuild ? (
        <Modal title="Build evidence pack" onClose={() => setShowBuild(false)}>
          <p>Choose the scope, window, and frameworks a reviewer should see.</p>
          <div className="tf-form-grid">
            <label className="tf-field">Since
              <input className="tf-input" type="date" value={since} onChange={(event) => setSince(event.target.value)} />
            </label>
            <label className="tf-field">Until
              <input className="tf-input" type="date" value={until} onChange={(event) => setUntil(event.target.value)} />
            </label>
            <label className="tf-field" style={{ gridColumn: "1 / -1" }}>Recipients
              <input className="tf-input" placeholder="security@customer.com" value={recipients} onChange={(event) => setRecipients(event.target.value)} />
            </label>
          </div>
          <p className="tf-muted" style={{ marginTop: 10, fontSize: 12 }}>Packs cover the whole environment; the date range scopes the reviewer report and control coverage.</p>
          <div className="tf-field" style={{ marginTop: 14 }}>
            Frameworks
            <div className="tf-framework-picker">
              {FRAMEWORK_OPTIONS.map((framework) => (
                <label key={framework.id} className={`tf-check ${frameworks.includes(framework.id) ? "checked" : ""}`}>
                  <input
                    type="checkbox"
                    checked={frameworks.includes(framework.id)}
                    onChange={() => toggleFramework(framework.id)}
                  />
                  {framework.name}
                </label>
              ))}
            </div>
          </div>
          <div className="tf-modal-actions">
            <Button variant="ghost" onClick={() => setShowBuild(false)}>Cancel</Button>
            <Button
              variant="primary"
              onClick={() => create.mutate()}
              disabled={create.isPending || !frameworks.length}
            >
              {create.isPending ? "Building…" : "Build evidence pack"}
            </Button>
          </div>
        </Modal>
      ) : null}
    </>
  );
}

function SectionTitle({ title, note }: { title: string; note: string }) {
  return (
    <div className="tf-section-title">
      <h2>{title}</h2>
      <span>{note}</span>
    </div>
  );
}

function ChecklistItem({ done, label, optional }: { done: boolean; label: string; optional?: boolean }) {
  return (
    <div className={`tf-checklist-item ${done ? "done" : ""}`}>
      <span className="tf-checklist-mark">{done ? "✓" : "·"}</span>
      <span>{label}</span>
      {optional && !done ? <Badge tone="warn">optional</Badge> : null}
    </div>
  );
}
