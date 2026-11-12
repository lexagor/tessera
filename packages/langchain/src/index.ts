import { DynamicStructuredTool } from "@langchain/core/tools";
import type { StructuredToolInterface } from "@langchain/core/tools";
import type { z } from "zod";

import {
  wrapFn,
  type AgentMetadataInput,
  type EphemeralCredential,
  type PrincipalInput,
  type TesseraClient,
} from "@tessera/sdk-ts";

export interface WrapLangChainOptions<T> {
  intent: string;
  run: (args: Record<string, unknown>, credential: EphemeralCredential) => Promise<T>;
  schema?: z.ZodTypeAny;
  toolSchemaHash?: string;
  principal?: PrincipalInput;
  agentMeta?: AgentMetadataInput;
  requestedScopes?: string[];
  riskClass?: string;
  declaredPurpose?: string;
  authorityToken?: string;
}

/**
 * Wrap a LangChain `DynamicStructuredTool` so every invocation is authorized, executed with
 * a scoped credential (or broker-held grant), and recorded. The original tool is not invoked
 * unless the caller's `run` function chooses to do so.
 */
export function wrapLangChainTool<T>(
  client: TesseraClient,
  tool: StructuredToolInterface,
  options: WrapLangChainOptions<T>,
): DynamicStructuredTool {
  const schema =
    options.schema ??
    (tool as unknown as { schema?: z.ZodTypeAny }).schema;
  if (!schema) {
    throw new Error(
      "tessera: wrapLangChainTool needs a Zod schema on the tool or in options.schema",
    );
  }
  const wrapped = wrapFn<T>(
    client,
    {
      tool: tool.name,
      intent: options.intent,
      ...(options.toolSchemaHash ? { toolSchemaHash: options.toolSchemaHash } : {}),
      ...(options.principal ? { principal: options.principal } : {}),
      ...(options.agentMeta ? { agentMeta: options.agentMeta } : {}),
      ...(options.requestedScopes ? { requestedScopes: options.requestedScopes } : {}),
      ...(options.riskClass ? { riskClass: options.riskClass } : {}),
      ...(options.declaredPurpose ? { declaredPurpose: options.declaredPurpose } : {}),
      ...(options.authorityToken ? { authorityToken: options.authorityToken } : {}),
    },
    options.run,
  );

  return new DynamicStructuredTool({
    name: tool.name,
    description: tool.description,
    schema: schema as never,
    func: async (args: Record<string, unknown>) => wrapped(args),
  });
}
