import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";

import { api, environmentQuery } from "../api";
import { useWorkspace } from "../App";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorState,
  PageHeader,
  Skeleton,
} from "@tessera/ui";
import {
  CoverageMeter,
  DecisionDonut,
  Heatmap,
  TrendChart,
} from "../components/AnalyticsCharts";
import { TimeRangePicker } from "../components/TimeRange";
import {
  riskDistribution,
  riskLabel,
  riskOrder,
  riskTotal,
  type AnalyticsResult,
} from "../lib/analytics";
import { formatDuration, isTimeRange, type TimeRange } from "../lib/time";

export function AnalyticsPage() {
  const { environmentId } = useWorkspace();
  const [searchParams, setSearchParams] = useSearchParams();
  const rangeParam = searchParams.get("range");
  const range: TimeRange = isTimeRange(rangeParam) ? rangeParam : "14d";

  const query = useQuery({
    queryKey: ["analytics", environmentId, range],
    queryFn: () => api<AnalyticsResult>(`/v1/analytics?range=${range}${environmentId ? `&environmentId=${environmentId}` : ""}`),
    enabled: Boolean(environmentId),
  });

  function setRange(next: TimeRange) {
    const params = new URLSearchParams(searchParams);
    params.set("range", next);
    setSearchParams(params, { replace: true });
  }

  if (query.isLoading) {
    return (
      <>
        <PageHeader title="Analytics" subtitle="Loading action trends, control coverage, and proof latency." />
        <div className="tf-analytics-stats">
          {Array.from({ length: 5 }).map((_, index) => (
            <Card key={index}>
              <Skeleton width="42%" height={10} />
              <Skeleton width="58%" height={34} style={{ marginTop: 14 }} />
              <Skeleton width="78%" height={10} style={{ marginTop: 10 }} />
            </Card>
          ))}
        </div>
        <div className="tf-analytics-grid" style={{ marginTop: 16 }}>
          <Card><Skeleton height={220} /></Card>
          <Card><Skeleton height={220} /></Card>
        </div>
      </>
    );
  }

  if (query.isError || !query.data) {
    return (
      <>
        <PageHeader title="Analytics" subtitle="Action trends, control coverage, and proof latency." />
        <ErrorState
          title="Analytics are unavailable"
          message={query.error instanceof Error ? query.error.message : "Could not load analytics for this environment."}
          action={<Button onClick={() => query.refetch()}>Retry</Button>}
        />
      </>
    );
  }

  const analytics = query.data;
  const { totals, rates, verification } = analytics;
  const risk = riskDistribution(analytics.tools);
  const riskCount = Math.max(1, riskTotal(risk));
  const toolQuestions = analytics.tools.slice(0, 4);

  return (
    <>
      <PageHeader
        title="Analytics"
        subtitle="The questions a security buyer asks, answered with signed action records."
        actions={
          <>
            <TimeRangePicker value={range} onChange={setRange} />
            <Link className="tf-btn" to="/evidence">Evidence coverage</Link>
          </>
        }
      />

      {totals.actions === 0 ? (
        <Card>
          <EmptyState
            title="No actions in this window"
            action={<Link className="tf-btn primary" to="/keys">Instrument the first action</Link>}
          >
            Create an agent key, send one action through the broker, and the analytics will answer
            what happened, what was blocked, and whether it is provable.
          </EmptyState>
        </Card>
      ) : (
        <>
          <div className="tf-analytics-stats">
            <Card>
              <div className="tf-kpi-label">Actions</div>
              <div className="tf-analytics-metric">{totals.actions.toLocaleString()}</div>
              <div className="tf-muted">{analytics.window.days} day window · {totals.agents} agents</div>
            </Card>
            <Card>
              <div className="tf-kpi-label">Allow / deny rate</div>
              <div className="tf-analytics-metric">{Math.round(rates.allow * 100)}<span>%</span></div>
              <div className="tf-muted">{totals.allowed} allowed · {totals.denied} blocked</div>
            </Card>
            <Card>
              <div className="tf-kpi-label">Verified outcomes</div>
              <div className="tf-analytics-metric">{Math.round(rates.verifiedOutcome * 100)}<span>%</span></div>
              <div className="tf-muted">{totals.verified}/{totals.completed} completed records</div>
            </Card>
            <Card>
              <div className="tf-kpi-label">Policy coverage</div>
              <div className="tf-analytics-metric">{Math.round(rates.policyCoverage * 100)}<span>%</span></div>
              <div className="tf-muted">{totals.governed} governed · {totals.ungoverned} ungoverned</div>
            </Card>
            <Card>
              <div className="tf-kpi-label">Mean time to verification</div>
              <div className="tf-analytics-metric">{formatDuration(verification.averageSeconds)}</div>
              <div className="tf-muted">{verification.sample} verified records</div>
            </Card>
          </div>

          <div className="tf-analytics-grid">
            <Card className="tf-analytics-wide">
              <ChartHead
                title="Actions over time"
                question="Is agent activity changing, and are blocked calls rising with it?"
                aside={<Badge tone={totals.denied ? "warn" : "ok"}>{totals.denied} blocked</Badge>}
              />
              <TrendChart series={analytics.series} />
              <div className="tf-chart-legend">
                <span><i className="actions" />Actions</span>
                <span><i className="denied" />Blocked</span>
              </div>
            </Card>

            <Card>
              <ChartHead
                title="Allow / deny"
                question="How often is policy stopping an action?"
                aside={<Badge tone={totals.denied ? "warn" : "ok"}>{Math.round(rates.deny * 100)}% denied</Badge>}
              />
              <div className="tf-decision-body">
                <DecisionDonut allowed={totals.allowed} denied={totals.denied} />
                <div className="tf-decision-list">
                  <div><span>Allowed</span><strong>{totals.allowed}</strong></div>
                  <div><span>Blocked</span><strong>{totals.denied}</strong></div>
                  <div><span>Failed</span><strong>{totals.failed}</strong></div>
                </div>
              </div>
            </Card>

            <Card>
              <ChartHead
                title="Verified outcomes"
                question="Can I prove what happened?"
                aside={<Badge tone={rates.verifiedOutcome === 1 ? "ok" : "warn"}>{Math.round(rates.verifiedOutcome * 100)}%</Badge>}
              />
              <CoverageMeter value={rates.verifiedOutcome} label="Completed records verified" tone={rates.verifiedOutcome === 1 ? "ok" : "warn"} />
              <div className="tf-source-split">
                <div><span>Agent-reported</span><strong>{totals.agentReported}</strong></div>
                <div><span>Broker-observed</span><strong>{totals.brokerObserved}</strong></div>
              </div>
              <p className="tf-chart-note">Broker-observed outcomes are the stronger proof class for brokered credentials.</p>
            </Card>

            <Card>
              <ChartHead
                title="Risk distribution"
                question="Where is the blast radius concentrated?"
                aside={<Badge tone="muted">{totals.agents} agents</Badge>}
              />
              <div className="tf-risk-bar" aria-label="Risk distribution by action">
                {riskOrder().map((level) => (
                  <span
                    key={level}
                    className={`tf-risk-segment tf-risk-${level}`}
                    style={{ width: `${(risk[level] / riskCount) * 100}%` }}
                    title={`${riskLabel(level)}: ${risk[level]} actions`}
                  />
                ))}
              </div>
              <div className="tf-risk-legend">
                {riskOrder().map((level) => (
                  <div key={level}>
                    <span className={`tf-risk-dot tf-risk-${level}`} />
                    <span>{riskLabel(level)}</span>
                    <strong>{risk[level]}</strong>
                  </div>
                ))}
              </div>
              <div className="tf-top-tools">
                {toolQuestions.map((tool) => (
                  <div key={tool.tool}>
                    <span className="tf-mono">{tool.tool}</span>
                    <Badge tone={tool.denied ? "bad" : "muted"}>{tool.actions} actions</Badge>
                  </div>
                ))}
              </div>
            </Card>

            <Card>
              <ChartHead
                title="Policy coverage"
                question="How much traffic is governed by an explicit policy?"
                aside={<Badge tone={rates.policyCoverage === 1 ? "ok" : "warn"}>{Math.round(rates.policyCoverage * 100)}%</Badge>}
              />
              <CoverageMeter value={rates.policyCoverage} label="Governed actions" tone={rates.policyCoverage === 1 ? "ok" : "warn"} />
              <div className="tf-policy-breakdown">
                {analytics.policies.slice(0, 5).map((policy) => (
                  <div key={policy.policyId}>
                    <div>
                      <strong>{policy.policyId}</strong>
                      <span className="tf-muted">{policy.actions} actions · {policy.denied} blocked</span>
                    </div>
                    <Link className="tf-btn ghost" to={`/policies?policy=${encodeURIComponent(policy.policyId)}`}>Open</Link>
                  </div>
                ))}
              </div>
            </Card>

            <Card>
              <ChartHead
                title="Mean time to verification"
                question="How quickly can I produce proof after an action?"
              />
              <div className="tf-mttv-main">{formatDuration(verification.averageSeconds)}</div>
              <div className="tf-mttv-grid">
                <div><span>p50</span><strong>{formatDuration(verification.p50Seconds)}</strong></div>
                <div><span>p95</span><strong>{formatDuration(verification.p95Seconds)}</strong></div>
                <div><span>Sample</span><strong>{verification.sample}</strong></div>
              </div>
              <p className="tf-chart-note">Measured from the action timestamp to the first successful independent verification.</p>
            </Card>

            <Card className="tf-analytics-wide">
              <ChartHead
                title="Agent activity"
                question="Which agents are active, and when is the environment busiest?"
                aside={<Badge tone="muted">{analytics.heatmap.agents.length} agents</Badge>}
              />
              <Heatmap analytics={analytics} />
            </Card>
          </div>
        </>
      )}
    </>
  );
}

function ChartHead({
  title,
  question,
  aside,
}: {
  title: string;
  question: string;
  aside?: React.ReactNode;
}) {
  return (
    <div className="tf-chart-head">
      <div>
        <h2>{title}</h2>
        <p>{question}</p>
      </div>
      {aside}
    </div>
  );
}
