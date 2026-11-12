# @tessera-verify/verify

Independent verifier for Tessera v1 and v2 action records. Verification needs only the
receipt bytes and the broker's EIP-712 domain; it does not trust Tessera or the agent.

```bash
npm install @tessera-verify/verify
npx tessera-verify receipt.json
```

```ts
import { verifyReceipt, verifyAction } from "@tessera-verify/verify";

const result = verifyReceipt(receipt, {
  chainId: 84532,
  verifyingContract: "0x0000000000000000000000000000000000000000",
});
if (!result.valid) throw new Error(result.errors.join("; "));
```

`verifyAction` additionally checks that an outcome links to its authorization by
`authorizationReceiptId` (or the legacy immediate `prev` link) and shares its `actionId`.
