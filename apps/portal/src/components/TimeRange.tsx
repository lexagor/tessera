import { TIME_RANGES, type TimeRange } from "../lib/time";

export function TimeRangePicker({
  value,
  onChange,
  label = "Time range",
}: {
  value: TimeRange;
  onChange: (range: TimeRange) => void;
  label?: string;
}) {
  return (
    <div className="tf-time-range" role="group" aria-label={label}>
      {TIME_RANGES.map((range) => (
        <button
          key={range.id}
          className={`tf-time-range-option ${value === range.id ? "active" : ""}`}
          onClick={() => onChange(range.id)}
          aria-pressed={value === range.id}
        >
          {range.label}
        </button>
      ))}
    </div>
  );
}
