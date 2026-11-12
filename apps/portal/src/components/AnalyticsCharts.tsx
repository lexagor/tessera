import type { AnalyticsDay, AnalyticsResult } from "../lib/analytics";

function shortDay(day: string): string {
  return new Date(`${day}T00:00:00Z`).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
  });
}

export function TrendChart({ series }: { series: AnalyticsDay[] }) {
  const width = 720;
  const height = 240;
  const padding = { top: 18, right: 18, bottom: 34, left: 38 };
  const plotWidth = width - padding.left - padding.right;
  const plotHeight = height - padding.top - padding.bottom;
  const max = Math.max(1, ...series.map((day) => day.actions));
  const slot = plotWidth / Math.max(1, series.length);
  const barWidth = Math.max(4, Math.min(28, slot * 0.55));
  const bottom = padding.top + plotHeight;
  const grid = [0, 0.25, 0.5, 0.75, 1];
  return (
    <svg
      className="tf-trend-chart"
      viewBox={`0 0 ${width} ${height}`}
      role="img"
      aria-label={`Actions per day over ${series.length} days`}
    >
      {grid.map((ratio) => {
        const y = padding.top + plotHeight * ratio;
        return (
          <g key={ratio}>
            <line x1={padding.left} x2={width - padding.right} y1={y} y2={y} className="tf-chart-grid" />
            <text x={padding.left - 8} y={y + 3} textAnchor="end" className="tf-chart-axis">
              {Math.round(max * (1 - ratio))}
            </text>
          </g>
        );
      })}
      {series.map((day, index) => {
        const x = padding.left + index * slot + (slot - barWidth) / 2;
        const barHeight = (day.actions / max) * plotHeight;
        const deniedHeight = (day.denied / max) * plotHeight;
        return (
          <g key={day.day}>
            <title>
              {shortDay(day.day)}: {day.actions} actions, {day.denied} blocked, {day.failed} failed
            </title>
            <rect
              x={x}
              y={bottom - barHeight}
              width={barWidth}
              height={Math.max(day.actions ? 2 : 0, barHeight)}
              rx={2}
              className="tf-chart-bar"
            />
            {day.denied ? (
              <rect
                x={x}
                y={bottom - deniedHeight}
                width={barWidth}
                height={Math.max(2, deniedHeight)}
                rx={2}
                className="tf-chart-bar-denied"
              />
            ) : null}
            {index === 0 || index === series.length - 1 || index % Math.max(1, Math.ceil(series.length / 6)) === 0 ? (
              <text x={x + barWidth / 2} y={height - 10} textAnchor="middle" className="tf-chart-axis">
                {shortDay(day.day)}
              </text>
            ) : null}
          </g>
        );
      })}
    </svg>
  );
}

export function DecisionDonut({
  allowed,
  denied,
}: {
  allowed: number;
  denied: number;
}) {
  const total = Math.max(1, allowed + denied);
  const allowedRatio = allowed / total;
  const circumference = 2 * Math.PI * 46;
  return (
    <div className="tf-donut-wrap" role="img" aria-label={`${allowed} allowed, ${denied} denied`}>
      <svg viewBox="0 0 120 120" className="tf-donut">
        <circle cx="60" cy="60" r="46" className="tf-donut-track" />
        <circle
          cx="60"
          cy="60"
          r="46"
          className="tf-donut-allowed"
          strokeDasharray={`${allowedRatio * circumference} ${circumference}`}
          transform="rotate(-90 60 60)"
        />
        <circle
          cx="60"
          cy="60"
          r="46"
          className="tf-donut-denied"
          strokeDasharray={`${(1 - allowedRatio) * circumference} ${circumference}`}
          strokeDashoffset={-allowedRatio * circumference}
          transform="rotate(-90 60 60)"
        />
      </svg>
      <div className="tf-donut-center">
        <strong>{Math.round((denied / total) * 100)}%</strong>
        <span>denied</span>
      </div>
    </div>
  );
}

export function CoverageMeter({
  value,
  label,
  tone = "ok",
}: {
  value: number;
  label: string;
  tone?: "ok" | "warn" | "bad";
}) {
  const percent = Math.round(Math.max(0, Math.min(1, value)) * 100);
  return (
    <div className={`tf-coverage-meter ${tone}`}>
      <div className="tf-coverage-meter-head">
        <span>{label}</span>
        <strong>{percent}%</strong>
      </div>
      <div className="tf-coverage-meter-track">
        <span style={{ width: `${percent}%` }} />
      </div>
    </div>
  );
}

export function Heatmap({ analytics }: { analytics: AnalyticsResult }) {
  const { agents, days, cells } = analytics.heatmap;
  if (!agents.length || !days.length) {
    return <p className="tf-muted">No agent activity in this window.</p>;
  }
  const map = new Map(cells.map((cell) => [`${cell.agentId}|${cell.day}`, cell]));
  const max = Math.max(1, ...cells.map((cell) => cell.actions));
  return (
    <div className="tf-heatmap-scroll">
      <table className="tf-heatmap">
        <thead>
          <tr>
            <th scope="col">Agent</th>
            {days.map((day) => (
              <th scope="col" key={day}>
                <span>{shortDay(day)}</span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {agents.map((agent) => (
            <tr key={agent.agentId}>
              <th scope="row">{agent.agentId}</th>
              {days.map((day) => {
                const cell = map.get(`${agent.agentId}|${day}`);
                const actions = cell?.actions ?? 0;
                const intensity = actions ? Math.min(4, Math.ceil((actions / max) * 4)) : 0;
                return (
                  <td key={day}>
                    <span
                      className={`tf-heat-cell heat-${intensity}`}
                      title={`${agent.agentId} · ${shortDay(day)} · ${actions} actions${cell?.denied ? ` · ${cell.denied} denied` : ""}`}
                      aria-label={`${agent.agentId}, ${shortDay(day)}, ${actions} actions`}
                    >
                      {actions || ""}
                    </span>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function MiniSpark({ values }: { values: number[] }) {
  const width = 160;
  const height = 42;
  const points = values.length > 1 ? values : [0, 0];
  const max = Math.max(1, ...points);
  const coords = points.map((value, index) => {
    const x = (index / (points.length - 1)) * (width - 4) + 2;
    const y = height - 3 - (value / max) * (height - 8);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  return (
    <svg className="tf-mini-spark" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Trend">
      <polyline points={coords.join(" ")} fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
