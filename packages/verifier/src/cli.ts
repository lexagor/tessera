#!/usr/bin/env node
import { readFileSync } from "node:fs";

import type { AnyReceipt } from "@tessera-verify/receipt-schema";

import {
  ChainEntry,
  VerifyDomain,
  verifyAction,
  verifyChain,
  verifyReceipt,
} from "./index.js";

interface Input {
  receipt?: AnyReceipt;
  authorization?: AnyReceipt;
  outcome?: AnyReceipt;
  entries?: ChainEntry[];
  domain?: VerifyDomain;
}

function usage(): never {
  console.error(
    [
      "Usage: tessera-verify <file.json> [options]",
      "",
      "Options:",
      "  --chain-id <id>            EIP-712 chain id",
      "  --contract <address>       EIP-712 verifying contract",
      "  --expected-signer <addr>   Require a specific signer",
      "  --json                     Print the raw result (default)",
      "",
      "The file may contain a receipt, an {authorization,outcome} pair, a chain",
      "({entries:[...]}), or a top-level {domain:{chainId,verifyingContract}}.",
    ].join("\n"),
  );
  process.exit(2);
}

function argValue(args: string[], name: string): string | undefined {
  const index = args.indexOf(name);
  if (index === -1) return undefined;
  return args[index + 1];
}

const args = process.argv.slice(2);
if (args.length === 0 || args.includes("--help") || args.includes("-h")) usage();
const file = args.find((arg) => !arg.startsWith("--")) ?? usage();

let input: Input;
try {
  input = JSON.parse(readFileSync(file, "utf8")) as Input;
} catch (error) {
  console.error(`cannot read ${file}: ${error instanceof Error ? error.message : error}`);
  process.exit(2);
}

const chainId = argValue(args, "--chain-id") ?? input.domain?.chainId;
const contract = argValue(args, "--contract") ?? input.domain?.verifyingContract;
if (chainId === undefined || !contract) {
  console.error("domain required: pass --chain-id and --contract or include domain in the file");
  process.exit(2);
}
const domain: VerifyDomain = { chainId: Number(chainId), verifyingContract: contract };
const expectedSigner = argValue(args, "--expected-signer");

let result;
if (input.entries) {
  result = verifyChain(input.entries, domain, expectedSigner);
} else if (input.authorization && input.outcome) {
  result = verifyAction(input.authorization, input.outcome, domain, expectedSigner);
} else if (input.receipt) {
  result = verifyReceipt(input.receipt, domain, expectedSigner);
} else if ("v" in input) {
  result = verifyReceipt(input as unknown as AnyReceipt, domain, expectedSigner);
} else {
  console.error("no receipt, action pair, or chain found in the file");
  process.exit(2);
}

console.log(JSON.stringify(result, null, 2));
const matches = "matchesExpected" in result ? result.matchesExpected !== false : true;
process.exit(result.valid && matches ? 0 : 1);
