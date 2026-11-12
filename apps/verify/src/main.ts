import {
  verifyAction,
  verifyChain,
  verifyReceipt,
  type ChainEntry,
  type VerifyDomain,
} from "@tessera-verify/verify";
import type { AnyReceipt } from "@tessera-verify/receipt-schema";

import { buildTrustView, extractRecords, tamperPayload } from "./view-model.js";

const $ = <T extends HTMLElement>(id: string): T => {
  const element = document.getElementById(id);
  if (!element) throw new Error(`missing #${id}`);
  return element as T;
};

const VITE_ENV = (
  import.meta as {
    env?: {
      VITE_API_BASE_URL?: string;
      VITE_SITE_URL?: string;
      VITE_APP_URL?: string;
    };
  }
).env;
const API_BASE = VITE_ENV?.VITE_API_BASE_URL ?? "";
const IS_LOCAL = ["localhost", "127.0.0.1", "::1"].includes(window.location.hostname);
const SITE_URL = (
  VITE_ENV?.VITE_SITE_URL ?? (IS_LOCAL ? "http://localhost:8090" : "https://thetessera.xyz")
).replace(/\/$/, "");
const APP_URL = (
  VITE_ENV?.VITE_APP_URL ?? (IS_LOCAL ? "http://localhost:5173" : "https://app.thetessera.xyz")
).replace(/\/$/, "");

for (const link of Array.from(document.querySelectorAll<HTMLAnchorElement>("[data-site-link]"))) {
  link.href = `${SITE_URL}/`;
}
for (const link of Array.from(document.querySelectorAll<HTMLAnchorElement>("[data-site-path]"))) {
  link.href = `${SITE_URL}${link.dataset.sitePath ?? "/"}`;
}
for (const link of Array.from(document.querySelectorAll<HTMLAnchorElement>("[data-app-link]"))) {
  link.href = `${APP_URL}/`;
}

const input = $<HTMLTextAreaElement>("input");
const result = $<HTMLElement>("result");
const verdict = $<HTMLElement>("verdict");
const details = $<HTMLElement>("details");
const linkPanel = $<HTMLElement>("link-panel");
const linkTitle = $<HTMLElement>("link-title");
const linkSummary = $<HTMLElement>("link-summary");
const linkFacts = $<HTMLElement>("link-facts");
const trustPanel = $<HTMLElement>("trust-panel");
const trustSummary = $<HTMLElement>("trust-summary");
const enforcement = $<HTMLElement>("enforcement");
const trustFlow = $<HTMLElement>("trust-flow");
const tamperButton = $<HTMLButtonElement>("tamper");
const restoreButton = $<HTMLButtonElement>("restore");
const tamperNote = $<HTMLElement>("tamper-note");

let originalInput: string | null = null;
let tampered = false;

function escapeHtml(value: unknown): string {
  return String(value ?? "").replace(/[&<>"']/g, (character) => {
    switch (character) {
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

function domain(): VerifyDomain {
  const chainId = Number($<HTMLInputElement>("chain-id").value.trim());
  const verifyingContract = $<HTMLInputElement>("contract").value.trim();
  if (!Number.isFinite(chainId)) throw new Error("chainId must be a number");
  if (!/^0x[0-9a-fA-F]{40}$/.test(verifyingContract)) {
    throw new Error("verifyingContract must be a 20-byte address");
  }
  return { chainId, verifyingContract };
}

function expectedSigner(): string | undefined {
  const value = $<HTMLInputElement>("expected-signer").value.trim();
  return value.length > 0 ? value : undefined;
}

function resetTamper(): void {
  originalInput = null;
  tampered = false;
  tamperButton.hidden = false;
  restoreButton.hidden = true;
  tamperNote.hidden = true;
}

function renderTrust(
  records: { authorization?: Record<string, any>; outcome?: Record<string, any> | null; chainLength?: number },
  output: { valid: boolean; recovered?: string },
): void {
  if (!records.authorization) {
    trustPanel.hidden = true;
    enforcement.hidden = true;
    return;
  }
  const view = buildTrustView({
    authorization: records.authorization,
    outcome: records.outcome,
    chainLength: records.chainLength,
    verification: output,
    signer: expectedSigner(),
  });
  trustPanel.hidden = false;
  enforcement.hidden = false;
  enforcement.className = `enforcement ${view.enforcement.level === "Level 1" ? "level-1" : view.enforcement.level === "Level 2" ? "level-2" : "caller"}`;
  enforcement.textContent = view.enforcement.label;
  trustSummary.textContent = `${view.enforcement.detail} ${view.summary}`;
  trustFlow.innerHTML = view.entities
    .map(
      (entity, index) => `<div class="trust-step ${entity.state}">
        <span class="trust-index">${String(index + 1).padStart(2, "0")}</span>
        <span class="trust-marker"></span>
        <div class="trust-copy">
          <span class="trust-label">${escapeHtml(entity.label)}</span>
          <strong>${escapeHtml(entity.title)}</strong>
          <span>${escapeHtml(entity.detail)}</span>
          ${entity.hash ? `<code>${escapeHtml(entity.hash)}</code>` : ""}
        </div>
      </div>`,
    )
    .join("");
  tamperNote.hidden = !tampered;
  tamperNote.textContent = tampered
    ? "Simulated tampering: one signed field changed. The payload hash and signature no longer match. Restore the original to verify again."
    : "";
}

function render(
  label: string,
  output: { valid: boolean; errors: string[]; recovered?: string },
  records: { authorization?: Record<string, any>; outcome?: Record<string, any> | null; chainLength?: number },
): void {
  const matches =
    "matchesExpected" in output
      ? (output as { matchesExpected?: boolean }).matchesExpected !== false
      : true;
  const ok = output.valid && matches;
  result.hidden = false;
  verdict.textContent = ok ? `Valid — ${label}` : `Invalid — ${label}`;
  verdict.className = `verdict ${ok ? "valid" : "invalid"}`;
  const displayOutput = {
    ...output,
    valid: ok,
    errors: matches
      ? output.errors
      : [...output.errors, "signature does not recover to the expected signer"],
  };
  details.textContent = JSON.stringify(displayOutput, null, 2);
  renderTrust(records, { ...output, valid: ok });
}

function verify(): void {
  try {
    const body = JSON.parse(input.value) as {
      receipt?: AnyReceipt;
      authorization?: AnyReceipt;
      outcome?: AnyReceipt;
      entries?: ChainEntry[];
      v?: number;
    };
    const d = domain();
    const records = extractRecords(body);
    if (!expectedSigner()) {
      const attestationSigner = (records.authorization?.attestation as Record<string, any> | undefined)?.signerKeyId;
      if (typeof attestationSigner === "string" && /^0x[0-9a-fA-F]{40}$/.test(attestationSigner)) {
        $<HTMLInputElement>("expected-signer").value = attestationSigner;
      }
    }
    const signer = expectedSigner();
    if (body.entries) {
      render("chain", verifyChain(body.entries, d, signer), records);
    } else if (body.authorization && body.outcome) {
      render("action pair", verifyAction(body.authorization, body.outcome, d, signer), records);
    } else if (body.receipt) {
      render("receipt", verifyReceipt(body.receipt, d, signer), records);
    } else if (typeof body.v === "number") {
      render("receipt", verifyReceipt(body as unknown as AnyReceipt, d, signer), records);
    } else {
      throw new Error("expected a receipt, an {authorization,outcome} pair, or a chain");
    }
  } catch (error) {
    result.hidden = false;
    verdict.textContent = "Could not verify";
    verdict.className = "verdict invalid";
    details.textContent = error instanceof Error ? error.message : String(error);
    trustPanel.hidden = true;
  }
}

async function loadSample(): Promise<void> {
  const response = await fetch("./sample.json");
  if (!response.ok) throw new Error(`sample unavailable: ${response.status}`);
  const sample = (await response.json()) as {
    domain?: { chainId: number; verifyingContract: string };
    expectedSigner?: string;
    receipt?: unknown;
  };
  resetTamper();
  if (sample.domain) {
    $<HTMLInputElement>("chain-id").value = String(sample.domain.chainId);
    $<HTMLInputElement>("contract").value = sample.domain.verifyingContract;
  }
  if (sample.expectedSigner) $<HTMLInputElement>("expected-signer").value = sample.expectedSigner;
  input.value = JSON.stringify(sample, null, 2);
  verify();
}

$<HTMLButtonElement>("verify").addEventListener("click", verify);
$<HTMLButtonElement>("sample").addEventListener("click", () => {
  void loadSample();
});
$<HTMLButtonElement>("hero-sample").addEventListener("click", () => {
  void loadSample();
});
$<HTMLButtonElement>("clear").addEventListener("click", () => {
  input.value = "";
  result.hidden = true;
  trustPanel.hidden = true;
  resetTamper();
});
$<HTMLInputElement>("file").addEventListener("change", async (event) => {
  const file = (event.target as HTMLInputElement).files?.[0];
  if (!file) return;
  resetTamper();
  input.value = await file.text();
  verify();
});
tamperButton.addEventListener("click", () => {
  try {
    if (!originalInput) originalInput = input.value;
    const body = JSON.parse(input.value) as Record<string, any>;
    input.value = JSON.stringify(tamperPayload(body), null, 2);
    tampered = true;
    tamperButton.hidden = true;
    restoreButton.hidden = false;
    verify();
  } catch (error) {
    tamperNote.hidden = false;
    tamperNote.textContent = error instanceof Error ? error.message : String(error);
  }
});
restoreButton.addEventListener("click", () => {
  if (originalInput) input.value = originalInput;
  originalInput = null;
  tampered = false;
  tamperButton.hidden = false;
  restoreButton.hidden = true;
  tamperNote.hidden = true;
  verify();
});

interface PublicVerification {
  expiresAt: string;
  domain: { chainId: number; verifyingContract: string } | null;
  signer: string | null;
  verification: { valid: boolean; errors: string[]; recovered?: string };
  records: { authorization?: AnyReceipt; outcome?: AnyReceipt | null };
}

function fact(label: string, value: string): HTMLElement {
  const element = document.createElement("div");
  element.className = "fact";
  element.textContent = label;
  const strong = document.createElement("strong");
  strong.textContent = value || "—";
  element.appendChild(strong);
  return element;
}

async function loadVerificationLink(token: string): Promise<void> {
  linkPanel.hidden = false;
  linkTitle.textContent = "Verification link";
  linkSummary.textContent = "Loading the signed record…";
  linkFacts.replaceChildren();
  resetTamper();
  try {
    const response = await fetch(`${API_BASE.replace(/\/$/, "")}/v1/public/verify/${encodeURIComponent(token)}`);
    const body = (await response.json()) as PublicVerification & { error?: { message?: string } };
    if (!response.ok) throw new Error(body.error?.message ?? `verification link returned ${response.status}`);
    const authorization = body.records.authorization as Record<string, any> | undefined;
    const outcome = body.records.outcome as Record<string, any> | null | undefined;
    const principal = authorization?.principal as Record<string, any> | undefined;
    const policy = authorization?.policy as Record<string, any> | undefined;
    const valid = body.verification.valid;
    linkTitle.textContent = valid ? "Valid action record" : "Record could not be verified";
    linkTitle.style.color = valid ? "var(--accent)" : "var(--bad)";
    linkSummary.textContent = `${authorization?.agent ?? "The agent"} acted for ${principal?.principalId ?? authorization?.user ?? "a principal"} through ${authorization?.call?.tool ?? "a tool"}.`;
    linkFacts.append(
      fact("Decision", String(authorization?.authorization?.decision ?? "—")),
      fact("Outcome", String(outcome?.outcome?.status ?? "not recorded")),
      fact("Outcome source", String(outcome?.outcome?.source ?? "—")),
      fact("Policy", `${policy?.policyId ?? "—"} v${policy?.policyVersion ?? "—"}`),
      fact("Credential", String(authorization?.credential?.credentialType ?? authorization?.credential?.issuer ?? "—")),
      fact("Expires", new Date(body.expiresAt).toLocaleString()),
      fact("Signer", body.signer ?? body.verification.recovered ?? "—"),
    );
    if (body.domain) {
      $<HTMLInputElement>("chain-id").value = String(body.domain.chainId);
      $<HTMLInputElement>("contract").value = body.domain.verifyingContract;
    }
    if (body.signer) $<HTMLInputElement>("expected-signer").value = body.signer;
    input.value = JSON.stringify(body.records, null, 2);
    verify();
  } catch (error) {
    linkTitle.textContent = "Link unavailable";
    linkTitle.style.color = "var(--bad)";
    linkSummary.textContent = error instanceof Error ? error.message : String(error);
  }
}

const linkToken = window.location.pathname.match(/^\/verify\/([^/]+)$/)?.[1];
if (linkToken) void loadVerificationLink(linkToken);
if (new URLSearchParams(window.location.search).get("sample") === "1") {
  void loadSample();
}
