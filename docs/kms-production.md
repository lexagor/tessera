# Production Signing and KMS/HSM

The broker already supports a `DigestSigner` abstraction: `LocalSigner` for development and
`HttpKmsSigner` for an external KMS/HSM bridge (`KMS_SIGNER_URL`, `KMS_SIGNER_ADDRESS`).
Receipt and anchor signing fail closed if the bridge errors; there is no unsigned fallback.

## Current live state

Production still uses `BROKER_SIGNING_KEY` in the host secret store. That is an in-process key,
not managed KMS/HSM custody. Do not claim KMS/HSM-backed signing for the live deployment.

## Moving production to a managed key

1. Provision an secp256k1-capable key in the chosen KMS/HSM (AWS KMS `ECC_SECG_P256K1` or an
   operator HSM). Record the public address and key id.
2. Deploy a small bridge that accepts `POST /sign {"digest":"0x..."}` and returns
   `{"signature":"0x<r||s||v>","address":"0x..."}`. The bridge must authenticate the broker,
   enforce a timeout, and never log the digest or key material.
3. Set `KMS_SIGNER_URL` and `KMS_SIGNER_ADDRESS` on the broker; remove `BROKER_SIGNING_KEY` and
   `ANCHOR_PK` from the production environment.
4. Verify `/v1/verify/domain` returns the expected signer and run a signed receipt + chain
   verification.
5. Test bridge failure, timeout, malformed signature, and key rotation. All must fail closed.
6. Back up the key policy and rotation runbook in the operator secret store.

The broker's existing test suite includes a mock KMS bridge (`kms_signer`). A real cloud KMS
run is an external validation step; it is not covered by this repository.
