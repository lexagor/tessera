import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, NavLink, Navigate, Route, Routes, useLocation } from "react-router-dom";

import { getMe, logout, type Me } from "./api";
import { ActionsPage } from "./pages/Actions";
import { DesignsPage } from "./pages/Designs";
import { ActionDetailPage } from "./pages/ActionDetail";
import { AgentsPage } from "./pages/Agents";
import { AgentDetailPage } from "./pages/AgentDetail";
import { EvidencePage } from "./pages/Evidence";
import { EvidenceDetailPage } from "./pages/EvidenceDetail";
import { TransitionsPage } from "./pages/Transitions";
import { InvitePage } from "./pages/Invite";
import { KeysPage } from "./pages/Keys";
import { LoginPage } from "./pages/Login";
import { OverviewPage } from "./pages/Overview";
import { PoliciesPage } from "./pages/Policies";
import { PublicEvidencePage } from "./pages/PublicEvidence";
import { PublicVerifyPage } from "./pages/PublicVerify";
import { ReviewsPage } from "./pages/Reviews";
import { SettingsPage } from "./pages/Settings";
import { TeamPage } from "./pages/Team";
import { applyDesign, DESIGNS, readDesign, type DesignId, type DesignMode } from "./design";

interface Workspace {
  me: Me;
  environmentId: string;
  setEnvironmentId: (id: string) => void;
  refresh: () => void;
}

const WorkspaceContext = createContext<Workspace | null>(null);

export function useWorkspace(): Workspace {
  const value = useContext(WorkspaceContext);
  if (!value) throw new Error("Workspace context is not available");
  return value;
}

export function App() {
  const [designState, setDesignState] = useState(readDesign);
  const { design, mode } = designState;
  const meQuery = useQuery({ queryKey: ["me"], queryFn: getMe, retry: false });
  const [environmentId, setEnvironmentIdState] = useState(
    () => localStorage.getItem("tessera.environment") ?? "",
  );
  const location = useLocation();
  const publicVerify = location.pathname.startsWith("/verify/");
  const publicInvite = location.pathname.startsWith("/invite/");
  const publicEvidence = location.pathname.startsWith("/evidence/share/");

  useEffect(() => {
    applyDesign(design, mode);
  }, [design, mode]);

  function selectDesign(id: DesignId) {
    const option = DESIGNS.find((item) => item.id === id) ?? DESIGNS[0]!;
    setDesignState({ design: id, mode: option.defaultMode });
  }

  function selectMode(next: DesignMode) {
    setDesignState((current) => ({ ...current, mode: next }));
  }

  function applyDesignChoice(id: DesignId, nextMode: DesignMode) {
    setDesignState({ design: id, mode: nextMode });
  }

  useEffect(() => {
    if (!meQuery.data) return;
    if (environmentId && meQuery.data.environments.some((environment) => environment.id === environmentId)) {
      return;
    }
    const first = meQuery.data.environments[0]?.id ?? "";
    setEnvironmentIdState(first);
    if (first) localStorage.setItem("tessera.environment", first);
  }, [environmentId, meQuery.data]);

  function setEnvironmentId(id: string) {
    setEnvironmentIdState(id);
    localStorage.setItem("tessera.environment", id);
  }

  const workspace = useMemo<Workspace | null>(() => {
    if (!meQuery.data) return null;
    return {
      me: meQuery.data,
      environmentId,
      setEnvironmentId,
      refresh: () => void meQuery.refetch(),
    };
  }, [environmentId, meQuery.data]);

  if (publicVerify) {
    return (
      <Routes>
        <Route path="/verify/:token" element={<PublicVerifyPage />} />
      </Routes>
    );
  }

  if (publicInvite) {
    return (
      <Routes>
        <Route path="/invite/:token" element={<InvitePage />} />
      </Routes>
    );
  }

  if (publicEvidence) {
    return (
      <Routes>
        <Route path="/evidence/share/:token" element={<PublicEvidencePage />} />
      </Routes>
    );
  }

  if (meQuery.isLoading) {
    return <div className="tf-login"><div className="tf-login-card">Loading…</div></div>;
  }

  if (meQuery.isError || !workspace) {
    return <LoginPage />;
  }

  return (
    <WorkspaceContext.Provider value={workspace}>
      <div className="tf-app">
        <aside className="tf-sidebar">
          <Link to="/" className="tf-brand">Tessera</Link>
          <p className="tf-tagline">Proof of action for AI agents</p>
          <nav className="tf-nav">
            <NavLink to="/" end>Overview</NavLink>
            <NavLink to="/actions">Actions</NavLink>
            <NavLink to="/agents">Agents</NavLink>
            <NavLink to="/evidence">Evidence</NavLink>
            <NavLink to="/reviews">Reviews</NavLink>
            <NavLink to="/transitions">Transitions</NavLink>
            <NavLink to="/designs">Designs</NavLink>
            <NavLink to="/policies">Policies</NavLink>
            <NavLink to="/keys">Agent keys</NavLink>
            <NavLink to="/team">Team</NavLink>
            <NavLink to="/settings">Settings</NavLink>
          </nav>
          <div className="tf-sidebar-foot">
            <div>{workspace.me.org.name}</div>
            <div className="tf-muted" style={{ marginTop: 4 }}>{workspace.me.role} · {workspace.me.org.plan}</div>
            <button
              className="tf-btn ghost"
              style={{ marginTop: 10, width: "100%" }}
              onClick={async () => {
                await logout();
                window.location.href = "/";
              }}
            >
              Sign out
            </button>
          </div>
        </aside>
        <main className="tf-main">
          <header className="tf-topbar">
            <div className="tf-org">
              <span>Environment</span>
              <select
                className="tf-select"
                style={{ width: 220 }}
                value={workspace.environmentId}
                onChange={(event) => workspace.setEnvironmentId(event.target.value)}
              >
                {workspace.me.environments.map((environment) => (
                  <option key={environment.id} value={environment.id}>
                    {environment.name}
                  </option>
                ))}
              </select>
            </div>
            <div className="tf-topbar-right">
              <div className="tf-design-controls">
                <label className="tf-muted" htmlFor="tf-design">Design</label>
                <select
                  id="tf-design"
                  className="tf-select"
                  value={design}
                  onChange={(event) => selectDesign(event.target.value as DesignId)}
                >
                  {DESIGNS.map((option) => (
                    <option key={option.id} value={option.id}>
                      {option.name}
                    </option>
                  ))}
                </select>
                <button
                  className="tf-btn ghost tf-theme-toggle"
                  onClick={() => selectMode(mode === "dark" ? "light" : "dark")}
                  aria-label={`Switch to ${mode === "dark" ? "light" : "dark"} mode`}
                >
                  {mode === "dark" ? "Light" : "Dark"}
                </button>
              </div>
              <span className="tf-muted">{workspace.me.user.email}</span>
            </div>
          </header>
          <div className="tf-page">
            <Routes>
              <Route path="/" element={<OverviewPage />} />
              <Route path="/actions" element={<ActionsPage />} />
              <Route path="/actions/:actionId" element={<ActionDetailPage />} />
              <Route path="/agents" element={<AgentsPage />} />
              <Route path="/agents/:agentId" element={<AgentDetailPage />} />
              <Route path="/evidence" element={<EvidencePage />} />
              <Route path="/evidence/:packId" element={<EvidenceDetailPage />} />
              <Route path="/reviews" element={<ReviewsPage />} />
              <Route path="/transitions" element={<TransitionsPage />} />
              <Route
                path="/designs"
                element={
                  <DesignsPage
                    design={design}
                    mode={mode}
                    onApply={applyDesignChoice}
                  />
                }
              />
              <Route path="/policies" element={<PoliciesPage />} />
              <Route path="/keys" element={<KeysPage />} />
              <Route path="/team" element={<TeamPage />} />
              <Route path="/invite/:token" element={<InvitePage />} />
              <Route path="/settings" element={<SettingsPage />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </div>
        </main>
      </div>
    </WorkspaceContext.Provider>
  );
}
