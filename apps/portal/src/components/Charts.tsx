import type { ReactNode } from "react";

import type { RiskLevel } from "../lib/risk";

export function Sparkline({
  values,
  width = 150,
  height = 38,
  label,
}: {
  values: number[];
  width?: number;
  height?: number;
  label?: string;
}) {
  const points = values.length > 1 ? values : [0, 0];
  const max = Math.max(1, ...points);
  const min = Math.min(...points);
  const range = Math.max(1, max - min);
  const coords = points.map((value, index) => {
    const x = (index / (points.length - 1)) * (width - 4) + 2;
    const y = height - 3 - ((value - min) / range) * (height - 8);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  return (
    <svg
      className="tf-sparkline"
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      role="img"
      aria-label={label ?? "Trend"}
    >
      <polyline points={coords.join(" ")} fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx={coords[coords.length - 1]!.split(",")[0]} cy={coords[coords.length - 1]!.split(",")[1]} r="2.6" fill="currentColor" />
    </svg>
  );
}

export function RiskBadge({ level }: { level: RiskLevel }) {
  return <span className={`tf-risk tf-risk-${level}`}>{level}</span>;
}

export function Stat({
  label,
  value,
  note,
  children,
  tone,
}: {
  label: string;
  value: ReactNode;
  note?: ReactNode;
  children?: ReactNode;
  tone?: "danger" | "warning" | "ok";
}) {
  return (
    <div className={`tf-stat ${tone ? `tf-stat-${tone}` : ""}`}>
      <div className="tf-kpi-label">{label}</div>
      <div className="tf-stat-value">{value}</div>
      {note ? <div className="tf-stat-note">{note}</div> : null}
      {children}
    </div>
  );
}
