import { canonicalize, keccak256Hex, toolDefinitionHash } from "@tessera-verify/receipt-schema";
import type {
  AgentMetadataInput,
  EphemeralCredential,
  PrincipalInput,
  TesseraClient,
} from "@tessera-verify/sdk-ts";

function hashResult(value: unknown): string {
  return keccak256Hex(canonicalize(value));
}

export interface McpToolCall {
  name: string;
  arguments: Record<string, unknown>;
}

export interface McpToolResult {
  content: Array<{ type: string; text?: string }>;
  isError?: boolean;
}

/**
 * Wrap an MCP server's tool dispatcher so every tool call is brokered by Tessera.
 *
 * Intercepts the MCP `tools/call` request, authorizes with the declared intent
 * (derived from tool name + optional metadata), injects the ephemeral credential, and
 * records the outcome (including failures). Tool *descriptions* are also sanitized
 * downstream by the (future) prompt-injection layer.
 */
export function wrapMcpDispatcher(
  client: TesseraClient,
  dispatch: (call: McpToolCall, credential?: EphemeralCredential) => Promise<McpToolResult>,
  opts: {
    intentFor?: (call: McpToolCall) => string;
    /**
     * Tool definitions from the server's `tools/list` response, keyed by tool name.
     * When present, each call carries the definition hash so the broker can detect
     * post-review redefinitions (rug pulls) for pinned tools.
     */
    toolDefinitions?: Record<string, unknown>;
    principal?: PrincipalInput;
    agentMeta?: AgentMetadataInput;
    requestedScopes?: string[];
    riskClass?: string;
    declaredPurpose?: string;
    authorityToken?: string;
  } = {},
) {
  return async function brokered(call: McpToolCall): Promise<McpToolResult> {
    const intent = opts.intentFor?.(call) ?? `invoke ${call.name}`;
    const definition = opts.toolDefinitions?.[call.name];
    const result = await client.authorize({
      tool: call.name,
      intent,
      args: call.arguments,
      ...(definition ? { toolSchemaHash: toolDefinitionHash(definition) } : {}),
      ...(opts.principal ? { principal: opts.principal } : {}),
      ...(opts.agentMeta ? { agentMeta: opts.agentMeta } : {}),
      ...(opts.requestedScopes ? { requestedScopes: opts.requestedScopes } : {}),
      ...(opts.riskClass ? { riskClass: opts.riskClass } : {}),
      ...(opts.declaredPurpose ? { declaredPurpose: opts.declaredPurpose } : {}),
      ...(opts.authorityToken ? { authorityToken: opts.authorityToken } : {}),
    });
    if (result.decision !== "allow" || !result.credential) {
      return { isError: true, content: [{ type: "text", text: "tessera: authorization denied" }] };
    }
    const brokerObservable = result.credential.material.kind === "grant";
    try {
      const out = await dispatch(call, result.credential);
      if (!brokerObservable) {
        const status = out.isError ? "failure" : "success";
        await client.record({
          receiptId: result.receiptId,
          resultHash: hashResult(out),
          status,
        });
      }
      return out;
    } catch (error) {
      if (!brokerObservable) {
        await client.record({
          receiptId: result.receiptId,
          resultHash: hashResult({ error: String(error) }),
          status: "failure",
          errorClass: error instanceof Error ? error.name : "Error",
        });
      }
      throw error;
    }
  };
}
