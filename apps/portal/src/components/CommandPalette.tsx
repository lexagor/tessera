import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";

import { api } from "../api";
import { useWorkspace } from "../App";
import type { SearchResult } from "../lib/analytics";

interface PaletteResult {
  id: string;
  group: string;
  title: string;
  subtitle: string;
  href: string;
  mark: string;
}

const PAGES: PaletteResult[] = [
  { id: "page-overview", group: "Navigate", title: "Overview", subtitle: "Current control-plane posture", href: "/", mark: "O" },
  { id: "page-analytics", group: "Navigate", title: "Analytics", subtitle: "Action trends and proof latency", href: "/analytics", mark: "A" },
  { id: "page-actions", group: "Navigate", title: "Actions", subtitle: "Searchable action evidence", href: "/actions", mark: "A" },
  { id: "page-agents", group: "Navigate", title: "Agents", subtitle: "Agent inventory and blast radius", href: "/agents", mark: "A" },
  { id: "page-integrations", group: "Navigate", title: "Integrations", subtitle: "Coverage and credential posture", href: "/integrations", mark: "I" },
  { id: "page-evidence", group: "Navigate", title: "Evidence", subtitle: "Framework coverage and reviewer packs", href: "/evidence", mark: "E" },
  { id: "page-reviews", group: "Navigate", title: "Reviews", subtitle: "Human approval queue", href: "/reviews", mark: "R" },
  { id: "page-policies", group: "Navigate", title: "Policies", subtitle: "Trust ladder and policy versions", href: "/policies", mark: "P" },
  { id: "page-keys", group: "Navigate", title: "Agent keys", subtitle: "Credentials and rotation", href: "/keys", mark: "K" },
];

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { environmentId } = useWorkspace();
  const navigate = useNavigate();
  const [search, setSearch] = useState("");
  const [active, setActive] = useState(0);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!open) return;
    setSearch("");
    setActive(0);
    window.setTimeout(() => input.current?.focus(), 20);
  }, [open]);

  useEffect(() => {
    setActive(0);
  }, [search]);

  const query = useQuery({
    queryKey: ["command-search", environmentId, search],
    queryFn: () => api<SearchResult>(`/v1/search?q=${encodeURIComponent(search)}`),
    enabled: open && search.trim().length >= 2,
    staleTime: 10_000,
  });

  const results = useMemo<PaletteResult[]>(() => {
    const needle = search.trim().toLowerCase();
    const pages = PAGES.filter(
      (page) =>
        !needle ||
        page.title.toLowerCase().includes(needle) ||
        page.subtitle.toLowerCase().includes(needle),
    );
    if (!needle) return pages;
    const data = query.data;
    if (!data) return pages;
    const actions = data.actions.map((action) => ({
      id: `action-${action.actionId}`,
      group: "Actions",
      title: action.tool,
      subtitle: `${action.agentId} · ${action.decision}`,
      href: `/actions/${action.actionId}`,
      mark: "A",
    }));
    const agents = data.agents.map((agent) => ({
      id: `agent-${agent.agentId}`,
      group: "Agents",
      title: agent.agentId,
      subtitle: `${agent.actions} actions`,
      href: `/agents/${encodeURIComponent(agent.agentId)}`,
      mark: "@",
    }));
    const policies = data.policies.map((policy) => ({
      id: `policy-${policy.id}`,
      group: "Policies",
      title: policy.name,
      subtitle: `${policy.id} · v${policy.version}${policy.mode ? ` · ${policy.mode}` : ""}`,
      href: `/policies?policy=${encodeURIComponent(policy.id)}`,
      mark: "P",
    }));
    const links = data.verificationLinks.map((link) => ({
      id: `link-${link.id}`,
      group: "Verification links",
      title: link.actionId,
      subtitle: `${link.tool} · shared ${new Date(link.createdAt).toLocaleDateString()}`,
      href: `/actions/${link.actionId}`,
      mark: "V",
    }));
    return [...actions, ...agents, ...policies, ...links, ...pages];
  }, [query.data, search]);

  const grouped = useMemo(() => {
    const map = new Map<string, Array<{ result: PaletteResult; index: number }>>();
    results.forEach((result, index) => {
      const current = map.get(result.group) ?? [];
      current.push({ result, index });
      map.set(result.group, current);
    });
    return [...map.entries()];
  }, [results]);

  if (!open) return null;

  function choose(result: PaletteResult) {
    onClose();
    navigate(result.href);
  }

  return (
    <div className="tf-command-backdrop" onClick={onClose}>
      <div
        className="tf-command"
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="tf-command-input-wrap">
          <span className="tf-command-icon">⌘</span>
          <input
            ref={input}
            className="tf-command-input"
            placeholder="Search agents, actions, policies, verification links…"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "ArrowDown") {
                event.preventDefault();
                setActive((current) => (results.length ? (current + 1) % results.length : 0));
              } else if (event.key === "ArrowUp") {
                event.preventDefault();
                setActive((current) => (results.length ? (current - 1 + results.length) % results.length : 0));
              } else if (event.key === "Enter" && results[active]) {
                event.preventDefault();
                choose(results[active]!);
              } else if (event.key === "Escape") {
                event.preventDefault();
                onClose();
              }
            }}
            role="combobox"
            aria-expanded="true"
            aria-controls="tf-command-results"
            aria-activedescendant={results[active] ? `command-${results[active]!.id}` : undefined}
          />
          <kbd>esc</kbd>
        </div>
        <div className="tf-command-results" id="tf-command-results" role="listbox">
          {search.trim().length >= 2 && query.isLoading ? (
            <div className="tf-command-message">Searching…</div>
          ) : null}
          {grouped.map(([group, entries]) => (
            <div className="tf-command-group" key={group}>
              <div className="tf-command-group-title">{group}</div>
              {entries.map(({ result, index }) => (
                <button
                  key={result.id}
                  id={`command-${result.id}`}
                  className={`tf-command-result ${active === index ? "active" : ""}`}
                  role="option"
                  aria-selected={active === index}
                  onMouseEnter={() => setActive(index)}
                  onClick={() => choose(result)}
                >
                  <span className="tf-command-mark">{result.mark}</span>
                  <span className="tf-command-copy">
                    <strong>{result.title}</strong>
                    <span>{result.subtitle}</span>
                  </span>
                  <span className="tf-command-enter">↵</span>
                </button>
              ))}
            </div>
          ))}
          {!results.length ? (
            <div className="tf-command-message">
              {search.trim().length < 2 ? "Type at least two characters to search." : "No matching records or pages."}
            </div>
          ) : null}
        </div>
        <div className="tf-command-foot">
          <span><kbd>↑</kbd><kbd>↓</kbd> navigate</span>
          <span><kbd>↵</kbd> open</span>
          <span><kbd>?</kbd> shortcuts</span>
        </div>
      </div>
    </div>
  );
}
