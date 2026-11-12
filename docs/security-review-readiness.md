# Agent Security Review Readiness

The questions an enterprise security reviewer asks about an agent, and the evidence Tessera
produces for each.

## The reviewer's questions

| Question | What they are really asking | Tessera evidence |
|---|---|---|
| Which agent acted? | Can you attribute the action to a named agent and version? | `agent`, `agentMeta.agentId`, `agentVersion`, `modelId`, `operatorId`, `environment` |
| On whose authority? | Did a human delegate this scope, and can you prove it? | `principal.principalId`, `authorityRef`, `authorityHash`, `verificationMethod` |
| What was it allowed to do? | Which policy version was evaluated, and what did it permit? | `policy.policyId`, `policyVersion`, `policyHash`, `evaluatedInputsHash` |
| What exactly did it call? | Which tool, definition, and arguments? | `call.tool`, `toolHash`, `argsHash`, `nonce` |
| What credential did it get? | Was the credential scoped and short-lived? | `credential.issuer`, `credentialType`, `thumbprint`, `scopes`, `ttlSeconds`, `singleUse` |
| What happened? | Did the action succeed, fail, or time out? | `outcome.status`, `resultHash`, `errorClass`, `externalRef`, `completedAt` |
| Can I verify it later? | Can a third party check the record without trusting the vendor? | `attestation.signerKeyId`, signature, chain link, open verifier |
| How long is it retained? | Does it meet records-retention rules? | Evidence pack + retention policy; SEC 17a-4 WORM export |

## Tabletop review checklist

1. Open the verification page with the reviewer.
2. Show the authorization record and the linked outcome record.
3. Recompute the payload hash and recover the signer offline.
4. Tamper with one field; show the verifier reject it.
5. Show the policy hash and the exact policy version.
6. Show the credential thumbprint and TTL.
7. Export the evidence pack; verify it on a machine that has no Tessera access.

## Control mapping

| Framework | Relevant surface | Tessera artifact |
|---|---|---|
| SOC 2 (CC6, CC7) | Logical access, monitoring, evidence | Action records, policy decisions, export |
| ISO 42001 | AI system operation and monitoring | Action records, human authority binding |
| EU AI Act Art. 12 | Record-keeping for high-risk systems | Tamper-evident action log, retention |
| EU AI Act Art. 26 | Deployer obligations, human oversight | Principal authority, approval records |
| FINRA | Supervision of agent actions | Per-action authorization and outcome |
| SEC 17a-4(f) | WORM retention | Append-only chain + signed export |
| DORA Art. 17 | ICT incident logging | Structured outcome and error class |
| NYDFS 500.6 | Audit trail and access controls | Tenant-scoped records, API-key audit |

## What is not claimed

- A receipt proves the broker signed the record; it does not prove the underlying provider
  executed correctly.
- The evidence pack maps records to controls; it is not a certification or legal opinion.
- SOC 2 Type I/II and a third-party pen test are on the roadmap, not current claims.
- The v2 `principal` binding is caller-attested unless an authority token is present. With an
  authority HMAC secret configured, the API derives short-lived HS256 tokens from the
  OIDC-authenticated session (owner-bound agent keys) or an explicit per-call token; the broker
  verifies the signature, issuer, audience, tenant/agent scope, expiry, and single-use `jti`,
  then records `verificationMethod: "hmac-jwt"`. The `verificationMethod` field always records
  which mode was used. Direct broker-side OIDC/JWKS verification and live IdP validation are
  not claimed yet.
