export type OidcAccessReason = "email_unverified" | "not_allowed";

export interface OidcAccessInput {
  production: boolean;
  email: string;
  emailVerified: boolean;
  allowedDomains: string[];
  allowedEmails: string[];
  unverifiedDemoEmails: string[];
  hasInvite: boolean;
  existingIdentity: boolean;
  bootstrapAllowed: boolean;
}

export type OidcAccessDecision =
  | { allowed: true }
  | { allowed: false; reason: OidcAccessReason };

export function evaluateOidcAccess(input: OidcAccessInput): OidcAccessDecision {
  const exactEmailAllowed = input.allowedEmails.includes(input.email);
  const unverifiedDemoAllowed =
    exactEmailAllowed &&
    input.unverifiedDemoEmails.includes(input.email) &&
    !input.emailVerified;
  if (input.production && !input.emailVerified && !unverifiedDemoAllowed) {
    return { allowed: false, reason: "email_unverified" };
  }
  if (input.existingIdentity) return { allowed: true };
  if (input.hasInvite) return { allowed: true };
  if (input.allowedDomains.some((domain) => input.email.endsWith(`@${domain}`))) {
    return { allowed: true };
  }
  if (exactEmailAllowed) return { allowed: true };
  if (input.bootstrapAllowed) return { allowed: true };
  return { allowed: false, reason: "not_allowed" };
}
