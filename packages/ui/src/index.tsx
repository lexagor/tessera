import {
  useEffect,
  useState,
  type ButtonHTMLAttributes,
  type CSSProperties,
  type ReactNode,
} from "react";

export function Button({
  variant = "default",
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "default" | "primary" | "ghost" | "danger";
}) {
  return <button className={`tf-btn ${variant === "default" ? "" : variant} ${className}`} {...props} />;
}

export function Badge({
  tone = "muted",
  children,
}: {
  tone?: "ok" | "bad" | "warn" | "muted";
  children: ReactNode;
}) {
  return <span className={`tf-badge ${tone}`}>{children}</span>;
}

export function Card({
  children,
  className = "",
  style,
}: {
  children: ReactNode;
  className?: string;
  style?: CSSProperties;
}) {
  return <div className={`tf-card ${className}`} style={style}>{children}</div>;
}

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="tf-page-head">
      <div>
        <h1>{title}</h1>
        {subtitle ? <p>{subtitle}</p> : null}
      </div>
      {actions ? <div className="tf-actions">{actions}</div> : null}
    </div>
  );
}

export function EmptyState({
  title,
  children,
  action,
}: {
  title: string;
  children?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="tf-empty">
      <h3>{title}</h3>
      {children ? <p>{children}</p> : null}
      {action ? <div className="tf-actions" style={{ justifyContent: "center", marginTop: 14 }}>{action}</div> : null}
    </div>
  );
}

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      variant="ghost"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1400);
        } catch {
          setCopied(false);
        }
      }}
    >
      {copied ? "Copied" : label}
    </Button>
  );
}

export function CopyRow({ value }: { value: string }) {
  return (
    <div className="tf-copy-row">
      <code className="tf-code">{value}</code>
      <CopyButton value={value} />
    </div>
  );
}

export function ErrorBanner({ message }: { message: string | null }) {
  if (!message) return null;
  return <div className="tf-error">{message}</div>;
}

export function ErrorState({
  title = "Something went wrong",
  message,
  action,
}: {
  title?: string;
  message: string;
  action?: ReactNode;
}) {
  return (
    <div className="tf-error-state" role="alert">
      <span className="tf-error-state-mark">!</span>
      <div>
        <h3>{title}</h3>
        <p>{message}</p>
        {action ? <div className="tf-actions" style={{ marginTop: 12 }}>{action}</div> : null}
      </div>
    </div>
  );
}

export function Skeleton({
  width = "100%",
  height = 14,
  style,
}: {
  width?: number | string;
  height?: number | string;
  style?: CSSProperties;
}) {
  return (
    <span
      className="tf-skeleton"
      style={{ width, height, ...style }}
      aria-hidden="true"
    />
  );
}

export function SkeletonTable({
  rows = 6,
  columns = 5,
}: {
  rows?: number;
  columns?: number;
}) {
  return (
    <div className="tf-skeleton-table" aria-label="Loading" role="status">
      {Array.from({ length: rows }).map((_, row) => (
        <div className="tf-skeleton-row" key={row}>
          {Array.from({ length: columns }).map((__, column) => (
            <Skeleton key={column} height={12} width={column === 0 ? "70%" : `${Math.max(32, 88 - column * 12)}%`} />
          ))}
        </div>
      ))}
    </div>
  );
}

export function Modal({
  title,
  children,
  onClose,
  wide = false,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
  wide?: boolean;
}) {
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  return (
    <div className="tf-modal-backdrop" onClick={onClose}>
      <div
        className={`tf-modal ${wide ? "tf-modal-wide" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onClick={(event) => event.stopPropagation()}
      >
        <h2>{title}</h2>
        {children}
      </div>
    </div>
  );
}

export function formatDate(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function shortHash(value: string | null | undefined, size = 10): string {
  if (!value) return "—";
  if (value.length <= size * 2 + 1) return value;
  return `${value.slice(0, size)}…${value.slice(-4)}`;
}
