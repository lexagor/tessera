import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "../api";
import { useWorkspace } from "../App";
import {
  Badge,
  Button,
  Card,
  CopyRow,
  EmptyState,
  ErrorBanner,
  PageHeader,
  formatDate,
} from "@tessera/ui";

interface Member {
  id: string;
  email: string;
  name: string | null;
  role: string;
  created_at: string;
}

interface Invite {
  id: string;
  email: string;
  role: string;
  expires_at: string;
  accepted_at: string | null;
  created_at: string;
}

export function TeamPage() {
  const { me } = useWorkspace();
  const queryClient = useQueryClient();
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("member");
  const [inviteUrl, setInviteUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const members = useQuery({
    queryKey: ["members"],
    queryFn: () => api<{ items: Member[] }>("/v1/members"),
  });
  const invites = useQuery({
    queryKey: ["invites"],
    queryFn: () => api<{ items: Invite[] }>("/v1/invites"),
  });

  const invite = useMutation({
    mutationFn: () =>
      api<{ inviteUrl: string }>("/v1/invites", {
        method: "POST",
        body: JSON.stringify({ email, role }),
      }),
    onSuccess: async (data) => {
      setInviteUrl(data.inviteUrl);
      setEmail("");
      setError(null);
      await queryClient.invalidateQueries({ queryKey: ["invites"] });
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  const canInvite = me.role === "owner" || me.role === "admin";

  return (
    <>
      <PageHeader
        title="Team"
        subtitle="Invite-only access. Members sign in with the email you invite."
      />
      <ErrorBanner message={error} />

      {canInvite ? (
        <Card style={{ marginBottom: 16 }}>
          <div className="tf-actions">
            <input
              className="tf-input"
              style={{ maxWidth: 320 }}
              placeholder="teammate@company.com"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
            />
            <select
              className="tf-select"
              style={{ maxWidth: 150 }}
              value={role}
              onChange={(event) => setRole(event.target.value)}
            >
              <option value="admin">Admin</option>
              <option value="member">Member</option>
              <option value="viewer">Viewer</option>
            </select>
            <Button
              variant="primary"
              onClick={() => invite.mutate()}
              disabled={invite.isPending || !email.trim()}
            >
              {invite.isPending ? "Inviting…" : "Invite"}
            </Button>
          </div>
          {inviteUrl ? (
            <div style={{ marginTop: 14 }}>
              <p className="tf-muted" style={{ marginBottom: 6 }}>
                Invite created. Share this URL with the invited teammate.
              </p>
              <CopyRow value={inviteUrl} />
            </div>
          ) : null}
        </Card>
      ) : null}

      <div className="tf-grid" style={{ gridTemplateColumns: "1.1fr .9fr" }}>
        <Card>
          <h2 style={{ margin: 0, fontSize: 18 }}>Members</h2>
          <table className="tf-table" style={{ marginTop: 10 }}>
            <thead>
              <tr><th>Email</th><th>Role</th><th>Joined</th></tr>
            </thead>
            <tbody>
              {members.data?.items.map((member) => (
                <tr key={member.id}>
                  <td>{member.email}</td>
                  <td><Badge tone={member.role === "owner" ? "ok" : "muted"}>{member.role}</Badge></td>
                  <td className="tf-muted">{formatDate(member.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
        <Card>
          <h2 style={{ margin: 0, fontSize: 18 }}>Pending invites</h2>
          {invites.data?.items.filter((item) => !item.accepted_at).length ? (
            <div className="tf-list" style={{ marginTop: 10 }}>
              {invites.data.items
                .filter((item) => !item.accepted_at)
                .map((item) => (
                  <div className="tf-list-row" key={item.id}>
                    <div>
                      <div>{item.email}</div>
                      <div className="tf-muted">{item.role} · expires {formatDate(item.expires_at)}</div>
                    </div>
                    <Badge tone="warn">pending</Badge>
                  </div>
                ))}
            </div>
          ) : (
            <EmptyState title="No pending invites">Invite a teammate to collaborate on evidence and policies.</EmptyState>
          )}
        </Card>
      </div>
    </>
  );
}
