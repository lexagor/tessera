export type Role = "owner" | "admin" | "member" | "viewer";

export interface User {
  id: string;
  email: string;
  name: string | null;
  oidc_issuer: string | null;
  oidc_subject: string | null;
}

export interface Membership {
  org_id: string;
  user_id: string;
  role: Role;
}

export interface Org {
  id: string;
  name: string;
  slug: string;
  plan: string;
  retention_days?: number;
  deletion_requested_at?: string | null;
  deletion_scheduled_for?: string | null;
}

export interface Environment {
  id: string;
  org_id: string;
  name: string;
  slug: string;
  broker_tenant: string;
  broker_key_enc: string | null;
  broker_key_id: string | null;
}

export interface SessionContext {
  sessionId: string;
  user: User;
  org: Org;
  role: Role;
}

export interface Variables {
  session: SessionContext;
}
