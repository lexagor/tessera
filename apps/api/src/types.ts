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
}

export interface Environment {
  id: string;
  org_id: string;
  name: string;
  slug: string;
  broker_tenant: string;
  broker_key_enc: string | null;
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
