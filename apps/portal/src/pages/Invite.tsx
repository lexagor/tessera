import { useQuery } from "@tanstack/react-query";
import { useParams } from "react-router-dom";

import { getAuthConfig } from "../api";

export function InvitePage() {
  const { token = "" } = useParams();
  const config = useQuery({ queryKey: ["auth-config"], queryFn: getAuthConfig, retry: false });
  return (
    <div className="tf-login">
      <div className="tf-login-card">
        <p className="tf-kpi-label">Tessera invite</p>
        <h1>You're invited.</h1>
        <p>
          Sign in with the email address that received this invitation. Access is granted
          automatically after OIDC login.
        </p>
        <div className="tf-actions" style={{ marginTop: 20 }}>
          {config.data?.oidc !== false ? (
            <a className="tf-btn primary" href="/auth/login">Continue with SSO</a>
          ) : null}
          {config.data?.devAuth ? (
            <a className="tf-btn ghost" href="/auth/dev-login">Dev sign in</a>
          ) : null}
        </div>
        <p className="tf-muted" style={{ marginTop: 16, fontSize: 12 }}>
          Invite reference: <span className="tf-mono">{token.slice(0, 10)}…</span>
        </p>
      </div>
    </div>
  );
}
