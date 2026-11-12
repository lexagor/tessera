export interface PrincipalInput {
  principalId: string;
  principalType?: string;
  authorityRef: string;
  authorityHash: string;
  verifiedAt?: string;
  verificationMethod?: string;
}

export interface AgentMetadataInput {
  agentVersion?: string;
  modelId?: string;
  operatorId?: string;
  environment?: string;
}

export interface TesseraConfig {
  /** Base URL of the Tessera control plane / broker. */
  endpoint: string;
  /** API key or short-lived SDK token. */
  apiKey: string;
  /** Identifies the calling agent (registered in the plane). */
  agentId: string;
  /** On whose behalf the agent acts (end user principal). */
  userId: string;
  /** Optional default TTL for issued credentials, in seconds. */
  defaultTtlSeconds?: number;
  /** Optional default authority binding sent with every authorize call. */
  principal?: PrincipalInput;
  /** Optional default agent metadata sent with every authorize call. */
  agentMeta?: AgentMetadataInput;
  /** Optional short-lived authority token for per-call delegation. */
  authorityToken?: string;
}

export interface AuthorizeInput {
  tool: string;
  intent: string;
  args: Record<string, unknown>;
  /**
   * Hash of the tool definition the agent was given (`toolDefinitionHash` from
   * `@tessera-verify/receipt-schema`). Required by the broker for tools pinned by the tenant;
   * a mismatch is denied as a definition drift (rug pull).
   */
  toolSchemaHash?: string;
  /** Overrides the client-level principal for this call. */
  principal?: PrincipalInput;
  /** Overrides the client-level agent metadata for this call. */
  agentMeta?: AgentMetadataInput;
  requestedScopes?: string[];
  riskClass?: string;
  declaredPurpose?: string;
  /** HS256 JWT minted by the tenant backend for the delegating principal. */
  authorityToken?: string;
}

/** Secret material returned by an issuer. */
export type CredentialMaterial =
  | {
      kind: "aws_sts";
      accessKeyId: string;
      secretAccessKey: string;
      sessionToken: string;
      expiration: string;
    }
  | { kind: "bearer"; token: string; expiration?: string | null }
  | { kind: "grant"; grantId: string; proxyRequired: boolean };

export interface EphemeralCredential {
  provider: string;
  resource: string;
  ttlSeconds: number;
  singleUse: boolean;
  argsHash: string;
  material: CredentialMaterial;
  /** Broker-side reference for credential-level revocation, if supported. */
  reference?: string | null;
  /** Non-secret issuance id bound into the v2 receipt thumbprint. */
  issuanceId?: string | null;
}

export interface GrantReceipt {
  v: number;
  tenant: string;
  agent: string;
  user: string;
  intentHash: string;
  authorization: {
    decision: "allow" | "deny";
    policy: string;
    policyVersion: number;
    resource: string;
    anomalyScore: number;
    policyHash?: string;
  };
  call: { tool: string; argsHash: string; resultHash?: string | null; toolHash?: string | null };
  grant: { provider: string; ttlS: number; singleUse: boolean; status: string };
  ts: string;
  nonce: string;
  prev?: string | null;
  authorizationReceiptId?: string;
  signature?: string | null;
  actionId?: string;
  principal?: Record<string, unknown>;
  agentMeta?: Record<string, unknown>;
  intent?: Record<string, unknown>;
  policy?: Record<string, unknown>;
  credential?: Record<string, unknown>;
  outcome?: Record<string, unknown>;
  attestation?: Record<string, unknown>;
}

export interface AuthorizeResult {
  decision: "allow" | "deny";
  reason: string;
  credential?: EphemeralCredential;
  receipt: GrantReceipt;
  /** Identifies the receipt for a later record() call. */
  receiptId: string;
  /** Stable id shared by the authorization and outcome records (v2+). */
  actionId?: string;
}

export interface RecordInput {
  /** The receiptId returned by authorize(). */
  receiptId: string;
  resultHash: string;
  /** Outcome status: success | failure | denied | timeout | unknown. */
  status?: string;
  errorClass?: string;
  externalRef?: string;
  completedAt?: string;
}

export interface ProxyRequest {
  /** The grantId from `credential.material` when kind === "grant". */
  grantId: string;
  /** The credential's argsHash (must match what the grant was bound to). */
  argsHash: string;
  method: string;
  /** Path relative to the provider base URL, e.g. "/v1/refunds". */
  path: string;
  query?: Array<[string, string]>;
  contentType?: string;
  body?: string;
}

export interface ProxyResponse {
  status: number;
  contentType?: string | null;
  body: string;
  actionId?: string;
  authorizationReceiptId?: string;
  outcomeReceiptId?: string;
  outcomeReceipt?: GrantReceipt;
  outcomeRecorded?: boolean;
}

/** A Merkle anchor batch for an agent's receipt chain. */
export interface AnchorBatch {
  root: string;
  count: number;
  leaves: string[];
  /** Ready-to-submit calldata for `ReceiptAnchor.anchor(bytes32,bytes32,uint64)`. */
  calldata: string;
  proof: string[];
}

/** A least-privilege policy proposed from the telemetry graph. */
export interface ProposedPolicy {
  policy: Record<string, unknown>;
  evidence: unknown[];
  notes: string[];
}

export interface RevocationEvent {
  id: string;
  tenant: string;
  target: string;
  kind: string;
  reason?: string | null;
  createdAt: string;
}

export interface RevokeOutcome {
  event: RevocationEvent;
  provider?: string | null;
  capability?: string | null;
  grantRevoked?: boolean | null;
  credentialRevoked?: boolean | null;
}

export interface ReceiptVerification {
  valid: boolean;
  recovered: string;
  payloadHash: string;
  matchesExpected?: boolean | null;
}

export interface ChainVerification {
  valid: boolean;
  length: number;
  recovered?: string | null;
}
