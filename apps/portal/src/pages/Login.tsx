import { useQuery } from "@tanstack/react-query";

import { getAuthConfig } from "../api";

export function LoginPage() {
  const config = useQuery({ queryKey: ["auth-config"], queryFn: getAuthConfig, retry: false });
  return (
    <div className="tf-login">
      <div className="tf-login-card">
        <p className="tf-kpi-label">Tessera</p>
        <h1>Prove every agent action.</h1>
        <p>
          Sign in to your workspace to see actions, generate verification links, and export
          evidence for your enterprise reviewers.
        </p>
        <div className="tf-actions" style={{ marginTop: 22 }}>
          {config.data?.oidc !== false ? (
            <a className="tf-btn primary" href="/auth/login">Continue with SSO</a>
          ) : null}
          {config.data?.devAuth ? (
            <a className="tf-btn ghost" href="/auth/dev-login">Dev sign in</a>
          ) : null}
        </div>
        <p className="tf-muted" style={{ marginTop: 18, fontSize: 12 }}>
          Access is invite-only. Ask your workspace owner for an invitation.
        </p>
      </div>
    </div>
  );
}
