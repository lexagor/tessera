# Authority transitions

Revocations, rotations, and scope changes are part of the audit evidence, not just a mutable
revocation list.

Tessera appends them to the tenant's signed, hash-linked key-event ledger. Each event carries
`transitionType`, `target`, a reason, and before/after details where applicable:

| Event | Source |
|---|---|
| `authority.granted` | API-key creation or `POST /v1/transitions` |
| `authority.revoked` | `POST /v1/revoke` for an agent, grant, or credential |
| `authority.rotated` | API-key renewal |
| `authority.narrowed` | auto-remediation or `POST /v1/transitions` |
| `authority.stepped_up` | `POST /v1/transitions` |
| `authority.granted` / `authority.delegated` / `authority.changed` | `POST /v1/transitions` |

The broker signs each event with the broker key and links it to the previous event hash.
`GET /v1/key-events` and the control-plane `GET /v1/transitions` return the ledger plus
`verified` / `signaturesValid` verdicts. Evidence packs include the same ledger.

The control plane exposes an admin-only `POST /v1/transitions` for operator-recorded
step-ups and similar events. Do not use it to rewrite action history: transition records are
append-only.
