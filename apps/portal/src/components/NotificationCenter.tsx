import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { api } from "../api";
import { useWorkspace } from "../App";
import { Badge } from "@tessera/ui";
import type { NotificationItem } from "../lib/analytics";

function storageKey(environmentId: string): string {
  return `tessera.notifications.read.${environmentId}`;
}

function readSet(environmentId: string): Set<string> {
  try {
    const value = window.localStorage.getItem(storageKey(environmentId));
    return new Set(value ? (JSON.parse(value) as string[]) : []);
  } catch {
    return new Set();
  }
}

export function NotificationCenter() {
  const { environmentId } = useWorkspace();
  const [open, setOpen] = useState(false);
  const [read, setRead] = useState<Set<string>>(() => readSet(environmentId));
  const panel = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    setRead(readSet(environmentId));
  }, [environmentId]);

  useEffect(() => {
    function onPointerDown(event: MouseEvent) {
      if (!open) return;
      const target = event.target as Node;
      if (panel.current?.contains(target) || button.current?.contains(target)) return;
      setOpen(false);
    }
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  const query = useQuery({
    queryKey: ["notifications", environmentId],
    queryFn: () => api<{ items: NotificationItem[] }>("/v1/notifications"),
    enabled: Boolean(environmentId),
    refetchInterval: 60_000,
  });

  const items = query.data?.items ?? [];
  const unread = items.filter((item) => !read.has(item.id));

  function persist(next: Set<string>) {
    setRead(next);
    try {
      window.localStorage.setItem(storageKey(environmentId), JSON.stringify([...next]));
    } catch {
      /* storage can fail in private contexts */
    }
  }

  function markRead(id: string) {
    persist(new Set([...read, id]));
  }

  function markAllRead() {
    persist(new Set(items.map((item) => item.id)));
  }

  return (
    <div className="tf-notification-wrap">
      <button
        ref={button}
        className="tf-icon-btn"
        onClick={() => setOpen((current) => !current)}
        aria-label={unread.length ? `${unread.length} unread alerts` : "Alerts"}
        aria-expanded={open}
        aria-haspopup="dialog"
        title="Alerts"
      >
        <svg viewBox="0 0 20 20" aria-hidden="true">
          <path d="M10 2.5a4.5 4.5 0 0 0-4.5 4.5v3.1L4 12.4v.6h12v-.6l-1.5-2.3V7A4.5 4.5 0 0 0 10 2.5Z" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
          <path d="M8 15a2 2 0 0 0 4 0" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
        </svg>
        {unread.length ? <span className="tf-notification-count" aria-live="polite">{unread.length}</span> : null}
      </button>
      {open ? (
        <div className="tf-notification-panel" ref={panel} role="dialog" aria-label="Alerts">
          <div className="tf-notification-head">
            <div>
              <div className="tf-kpi-label">Alerts</div>
              <h2>What needs attention</h2>
            </div>
            {items.length ? <button className="tf-link-btn" onClick={markAllRead}>Mark all read</button> : null}
          </div>
          {query.isError ? (
            <p className="tf-muted">Alerts could not be loaded.</p>
          ) : items.length ? (
            <div className="tf-notification-list">
              {items.map((item) => (
                <Link
                  key={item.id}
                  className={`tf-notification-item ${read.has(item.id) ? "read" : ""}`}
                  to={item.href}
                  onClick={() => {
                    markRead(item.id);
                    setOpen(false);
                  }}
                >
                  <span className={`tf-notification-dot ${item.severity}`} />
                  <span className="tf-notification-copy">
                    <strong>{item.title}</strong>
                    <span>{item.detail}</span>
                  </span>
                  {!read.has(item.id) ? <Badge tone={item.severity === "critical" ? "bad" : item.severity === "warning" ? "warn" : "muted"}>new</Badge> : null}
                </Link>
              ))}
            </div>
          ) : (
            <div className="tf-notification-empty">
              <strong>All clear</strong>
              <span>No reviews, failed outcomes, or integration gaps need attention.</span>
            </div>
          )}
          <div className="tf-notification-foot">
            <Link to="/reviews" onClick={() => setOpen(false)}>Open review queue</Link>
            <Link to="/integrations" onClick={() => setOpen(false)}>Open integrations</Link>
          </div>
        </div>
      ) : null}
    </div>
  );
}
