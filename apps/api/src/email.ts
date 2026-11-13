import { env } from "./env.js";

export interface EmailMessage {
  to: string;
  subject: string;
  text: string;
  html?: string;
  replyTo?: string;
}

export interface EmailResult {
  sent: boolean;
  provider: "disabled" | "resend";
  id?: string;
  error?: string;
}

export function emailConfigured(): boolean {
  return env.EMAIL_PROVIDER === "resend" && Boolean(env.EMAIL_API_KEY && env.EMAIL_FROM);
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => {
    switch (char) {
      case "&":
        return "&amp;";
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case '"':
        return "&quot;";
      default:
        return "&#39;";
    }
  });
}

/** Send through Resend's HTTP API. Disabled deployments keep the manual invite link flow. */
export async function sendEmail(message: EmailMessage): Promise<EmailResult> {
  if (!emailConfigured()) return { sent: false, provider: "disabled" };
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      authorization: `Bearer ${env.EMAIL_API_KEY}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      from: env.EMAIL_FROM,
      to: [message.to],
      subject: message.subject,
      text: message.text,
      ...(message.html ? { html: message.html } : {}),
      ...(message.replyTo ?? env.EMAIL_REPLY_TO
        ? { reply_to: message.replyTo ?? env.EMAIL_REPLY_TO }
        : {}),
    }),
    signal: AbortSignal.timeout(15_000),
  });
  const body = (await response.json().catch(() => null)) as { id?: string; message?: string } | null;
  if (!response.ok) {
    return {
      sent: false,
      provider: "resend",
      error: body?.message?.slice(0, 200) ?? `email provider returned ${response.status}`,
    };
  }
  return { sent: true, provider: "resend", id: body?.id };
}

export function inviteEmail(input: {
  to: string;
  inviteUrl: string;
  orgName: string;
  inviterEmail: string;
  role: string;
}): EmailMessage {
  const org = escapeHtml(input.orgName);
  const inviter = escapeHtml(input.inviterEmail);
  const role = escapeHtml(input.role);
  const url = escapeHtml(input.inviteUrl);
  return {
    to: input.to,
    subject: `You're invited to ${input.orgName} on Tessera`,
    text: [
      `${input.inviterEmail} invited you to ${input.orgName} on Tessera as ${input.role}.`,
      "",
      `Accept the invite: ${input.inviteUrl}`,
      "",
      "This link expires in 7 days. Sign in with this email address.",
      "If you were not expecting this invitation, you can ignore it.",
    ].join("\n"),
    html: `<p>${inviter} invited you to <strong>${org}</strong> on Tessera as ${role}.</p>
<p><a href="${url}">Accept the invite</a></p>
<p>This link expires in 7 days. Sign in with this email address.</p>
<p>If you were not expecting this invitation, you can ignore it.</p>`,
  };
}

export function deletionRequestEmail(input: {
  to: string;
  orgName: string;
  purgeAfter: string;
}): EmailMessage {
  return {
    to: input.to,
    subject: `Deletion requested for ${input.orgName} on Tessera`,
    text: [
      `A deletion request was recorded for ${input.orgName}.`,
      "",
      `The workspace will be purged after ${input.purgeAfter} unless the owner restores it before then.`,
      "Export any evidence you need before the purge date.",
      "",
      "If you did not request this, contact security@thetessera.xyz immediately.",
    ].join("\n"),
    html: `<p>A deletion request was recorded for <strong>${escapeHtml(input.orgName)}</strong>.</p>
<p>The workspace will be purged after <strong>${escapeHtml(input.purgeAfter)}</strong> unless the owner restores it before then. Export any evidence you need before the purge date.</p>
<p>If you did not request this, contact <a href="mailto:security@thetessera.xyz">security@thetessera.xyz</a> immediately.</p>`,
  };
}
