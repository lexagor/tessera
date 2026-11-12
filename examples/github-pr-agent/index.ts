/**
 * Example: a coding agent that opens a PR, brokered through Tessera.
 *
 * The agent receives a GitHub installation token scoped to a single repository and the
 * minimum permissions (contents:write, pull_requests:write) — never a long-lived PAT.
 *
 * Status: scaffold.
 */
import { createClient, wrapFn, type EphemeralCredential } from "@tessera-verify/sdk-ts";

const tessera = createClient({
  endpoint: process.env.TESSERA_ENDPOINT ?? "http://localhost:8787",
  apiKey: process.env.TESSERA_API_KEY ?? "tsk_demo_local",
  agentId: "repo-maintenance-agent",
  userId: "user_42",
});

async function createPullRequest(
  args: Record<string, unknown>,
  credential?: EphemeralCredential,
): Promise<{ url: string }> {
  const token = credential?.material.kind === "bearer" ? credential.material.token : undefined;
  console.log("using scoped installation token:", token?.slice(0, 6) ?? "(none)", "...");
  return { url: `https://github.com/${args.repo}/pull/1` };
}

async function main() {
  const openPr = wrapFn(
    tessera,
    { tool: "github.pulls.create", intent: "open a pull request fixing a lint error in this repo" },
    createPullRequest,
  );
  try {
    console.log(await openPr({ repo: "acme/widgets", title: "fix lint", head: "bot/fix" }));
  } catch (err) {
    console.error("brokered call failed:", String(err));
  }
}

main();
