export { TesseraClient, createClient } from "./client.js";
export type { CallOptions } from "./client.js";
export { hashResult, wrap, wrapFn, wrapProxy } from "./wrap.js";
export type { ToolRunner, WrapOptions } from "./wrap.js";
export type {
  TesseraConfig,
  PrincipalInput,
  AgentMetadataInput,
  AuthorizeInput,
  AuthorizeResult,
  EphemeralCredential,
  CredentialMaterial,
  GrantReceipt,
  RecordInput,
  ProxyRequest,
  ProxyResponse,
  AnchorBatch,
  ProposedPolicy,
  RevocationEvent,
  RevokeOutcome,
  ReceiptVerification,
  ChainVerification,
} from "./types.js";
