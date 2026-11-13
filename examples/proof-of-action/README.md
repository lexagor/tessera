# Proof of Action — verifiable records

These are two real signed Tessera records, not screenshots. Both can be checked offline with
the open verifier; the live record also has a hosted reviewer link.

## 1. Live production record — policy denial

- Public verifier: <https://verify.thetessera.xyz/verify/MF8r1-gEjpTqJkMXBftezBAfqhy6UORapo-xluIMlW4>
- File: [`live-denial.json`](live-denial.json)
- Signer: `0xc35374b171e3be80b62c7612479f4d65e519f4e6`
- Domain: chain `84532`, verifying contract `0x0000000000000000000000000000000000000000`

This record shows a **denied** `stripe.refunds.create` request for `amount: 4200` against a policy
that caps refunds at `100`. The broker issued **no credential** and made **no provider call**.
The signed record proves the policy decision and its bindings; it does not claim a refund
happened.

```bash
npm install @tessera-verify/verify
npx tessera-verify examples/proof-of-action/live-denial.json \
  --expected-signer 0xc35374b171e3be80b62c7612479f4d65e519f4e6
```

Expected result:

```json
{
  "valid": true,
  "recovered": "0xc35374b171e3be80b62c7612479f4d65e519f4e6",
  "payloadHash": "0x337973897995adf16b3dfe61be70054d5b15e51bcc87454971adbaa8cbc8f275",
  "matchesExpected": true,
  "errors": []
}
```

## 2. Sandbox allow + outcome record

- File: [`sandbox-action.json`](sandbox-action.json)
- Signer: `0x70997970c51812dc3a010c7d01b50e0d17dc79c8`
- Domain: chain `84532`, verifying contract `0x0000000000000000000000000000000000000000`

This is a local demo-broker run using the **mock Stripe issuer**. It contains a signed
authorization and a linked outcome receipt (`agent_reported`, result hash for a mock refund
`re_demo_4242`). It is a complete authorization → outcome pair, but **no real Stripe call and no
real money movement occurred**.

```bash
npm install @tessera-verify/verify
npx tessera-verify examples/proof-of-action/sandbox-action.json \
  --expected-signer 0x70997970c51812dc3a010c7d01b50e0d17dc79c8
```

Expected result:

```json
{
  "valid": true,
  "length": 2,
  "recovered": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
  "errors": []
}
```

## What is bound

The receipts bind the tenant, agent, principal (caller-asserted user for the sandbox; the live
record uses an API-minted authority subject), intent hash, policy id/version/hash, evaluated
inputs hash, tool, arguments hash, credential metadata, outcome hash/source, previous receipt,
and EIP-712 signature. The live denial has no credential/outcome by design.

## What this does not prove

- The live denial did not execute a provider call; it is an enforcement record.
- The sandbox outcome is caller-reported and uses a mock issuer; it is not a real refund.
- A valid signature proves which key signed the record, not that the underlying business event
  was lawful or executed correctly.
- Tessera records are tamper-evident, not tamper-proof.

See [`docs/receipt-spec.md`](../../docs/receipt-spec.md) and
[`docs/security-guarantees.md`](../../docs/security-guarantees.md) for the exact guarantees.
