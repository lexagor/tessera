# Evidence Packs and Reviewer Links

Evidence packs turn signed action records into a review-ready artifact. A pack has two parts:

1. a **signed tenant archive** containing receipts, policies, authority transitions, key events,
   checkpoints, and anchors; and
2. a **reviewer report** that maps the records to SOC 2, ISO 42001, EU AI Act, NIST AI RMF, and
   DORA controls, lists gaps, and explains what the evidence does and does not prove.

The report is a coverage summary, not a certification or legal opinion. Direct bearer and AWS
outcomes remain agent-reported; broker-held grants proxied by Tessera are broker-observed.

## Build a pack

```bash
curl -X POST "$TESSERA_API/v1/evidence-packs?environmentId=$ENV_ID" \
  -H "cookie: $SESSION" \
  -H "content-type: application/json" \
  -d '{
    "frameworks": ["soc2", "iso42001", "eu-ai-act", "nist-ai-rmf", "dora"],
    "since": "2026-10-01",
    "until": "2026-10-31",
    "recipients": ["security@customer.example"]
  }'
```

Packs cover the whole environment. The date range scopes the report and control coverage; the
archive contains the environment's signed evidence. `GET /v1/evidence/readiness` returns the same
coverage model without creating an archive.

## Reviewer links

Create a bearer link for an auditor:

```bash
curl -X POST "$TESSERA_API/v1/evidence-packs/$PACK_ID/share" \
  -H "cookie: $SESSION" \
  -H "content-type: application/json" \
  -d '{"expiresInDays": 30}'
```

The returned URL opens a public reviewer view. Anyone with the link can read the report and
download the archive until the link expires. Revoke it with:

```bash
curl -X DELETE "$TESSERA_API/v1/evidence-packs/$PACK_ID/share" -H "cookie: $SESSION"
```

## Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /v1/evidence/readiness` | Framework coverage, gaps, inventory, and proof health |
| `GET /v1/evidence-packs` | List packs with readiness and share state |
| `POST /v1/evidence-packs` | Build a pack and reviewer report |
| `GET /v1/evidence-packs/:id` | Pack metadata and stored snapshot |
| `GET /v1/evidence-packs/:id/report` | Reviewer report (HTML) |
| `GET /v1/evidence-packs/:id/download` | Signed archive (`.tar.gz`) |
| `POST /v1/evidence-packs/:id/share` | Create or rotate a reviewer link |
| `DELETE /v1/evidence-packs/:id/share` | Revoke the reviewer link |
| `GET /v1/public/evidence/:token` | Public reviewer summary |
| `GET /v1/public/evidence/:token/report` | Public reviewer report |
| `GET /v1/public/evidence/:token/download` | Public archive download |

## Verification

The archive remains independently verifiable. Download it, unpack it, and run the open verifier:

```bash
tar -xzf tessera-evidence-<id>.tar.gz
npx @tessera-verify/verify --archive . --expect-signer <signer-from-manifest>
```

The public verifier remains available for single-action links and offline receipt files.

## Object storage (optional)

By default, evidence archives are written under `EVIDENCE_DIR` on the API host. For off-host
retention, configure an S3-compatible bucket:

```bash
EVIDENCE_S3_BUCKET=tessera-evidence
EVIDENCE_S3_REGION=eu-central-1
EVIDENCE_S3_ENDPOINT=            # blank for AWS; set for MinIO/R2/B2 S3 API
EVIDENCE_S3_ACCESS_KEY=...
EVIDENCE_S3_SECRET_KEY=...
EVIDENCE_S3_PREFIX=evidence
EVIDENCE_S3_FORCE_PATH_STYLE=0   # 1 for most MinIO-style endpoints
```

The API stores the returned `s3://bucket/key` locator in `evidence_packs.object_key` and uses
the same locator for authenticated and reviewer-link downloads. Existing local packs continue
to work; new packs use the configured storage. Use a bucket policy that denies public access,
enables default encryption, and applies a lifecycle/retention rule that matches the tenant
retention period. Do not put long-lived object-storage credentials in the portal or broker.

When S3 evidence storage is enabled, the local `docker_evidence` volume is no longer the source
of truth. Back up the bucket with versioning/replication and test restore separately; do not
claim the local evidence archive covers it. The Postgres dump still contains the locator, so a
database restore requires the matching bucket objects.
