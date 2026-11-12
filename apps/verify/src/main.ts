import {
  verifyAction,
  verifyChain,
  verifyReceipt,
  type ChainEntry,
  type VerifyDomain,
} from "@tessera-verify/verify";
import type { AnyReceipt } from "@tessera-verify/receipt-schema";

const $ = <T extends HTMLElement>(id: string): T => {
  const element = document.getElementById(id);
  if (!element) throw new Error(`missing #${id}`);
  return element as T;
};

const API_BASE =
  (import.meta as { env?: { VITE_API_BASE_URL?: string } }).env?.VITE_API_BASE_URL ?? "";

const input = $<HTMLTextAreaElement>("input");
const result = $<HTMLElement>("result");
const verdict = $<HTMLElement>("verdict");
const details = $<HTMLElement>("details");
const linkPanel = $<HTMLElement>("link-panel");
const linkTitle = $<HTMLElement>("link-title");
const linkSummary = $<HTMLElement>("link-summary");
const linkFacts = $<HTMLElement>("link-facts");

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

function render(label: string, output: { valid: boolean; errors: string[] }) {
  const matches =
    "matchesExpected" in output
      ? (output as { matchesExpected?: boolean }).matchesExpected !== false
      : true;
  const ok = output.valid && matches;
  result.hidden = false;
  verdict.textContent = ok ? `Valid — ${label}` : `Invalid — ${label}`;
  verdict.className = `verdict ${ok ? "valid" : "invalid"}`;
  details.textContent = JSON.stringify(output, null, 2);
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
    const signer = expectedSigner();
    if (body.entries) {
      render("chain", verifyChain(body.entries, d, signer));
    } else if (body.authorization && body.outcome) {
      render("action pair", verifyAction(body.authorization, body.outcome, d, signer));
    } else if (body.receipt) {
      render("receipt", verifyReceipt(body.receipt, d, signer));
    } else if (typeof body.v === "number") {
      render("receipt", verifyReceipt(body as unknown as AnyReceipt, d, signer));
    } else {
      throw new Error("expected a receipt, an {authorization,outcome} pair, or a chain");
    }
  } catch (error) {
    result.hidden = false;
    verdict.textContent = "Could not verify";
    verdict.className = "verdict invalid";
    details.textContent = error instanceof Error ? error.message : String(error);
  }
}

async function loadSample(): Promise<void> {
  const response = await fetch("./sample.json");
  if (!response.ok) throw new Error(`sample unavailable: ${response.status}`);
  input.value = JSON.stringify(await response.json(), null, 2);
  verify();
}

$<HTMLButtonElement>("verify").addEventListener("click", verify);
$<HTMLButtonElement>("sample").addEventListener("click", () => {
  void loadSample();
});
$<HTMLButtonElement>("clear").addEventListener("click", () => {
  input.value = "";
  result.hidden = true;
});
$<HTMLInputElement>("file").addEventListener("change", async (event) => {
  const file = (event.target as HTMLInputElement).files?.[0];
  if (!file) return;
  input.value = await file.text();
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
