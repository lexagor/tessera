# Multi-AZ and Disaster Recovery Design

**Status:** target design and test plan. The live pilot is still a single VPS with single
Postgres and Redis. No multi-AZ failover has been tested.

## Target topology

- **Edge:** Cloudflare or equivalent WAF/DDoS + health-checked origin; two app hosts across
  zones or one autoscaling group.
- **App:** two or more stateless API/broker/portal/verifier instances behind a load balancer;
  Redis used for shared rate limits/replay cache (or moved to Postgres).
- **Database:** managed Postgres with Multi-AZ/standby, automated backups, PITR, and a
  non-superuser `tessera_app` role. RLS applied after every broker migration.
- **Redis:** managed Redis with replica/failover, AOF/durability appropriate to replay state.
- **Evidence:** S3-compatible object storage with versioning, encryption, and lifecycle policy.
- **Secrets:** cloud secret manager/KMS/HSM bridge, not a root-only `.env`.
- **Observability:** external metrics/logs/alerts, synthetic checks, on-call routing.

## Targets

| Scenario | RPO | RTO | Notes |
|---|---:|---:|---|
| API instance loss | 0 | < 5 min | Stateless instances behind LB |
| Postgres primary loss | < 5 min with PITR/standby | < 30 min | Managed failover + connection retry |
| Redis loss | Replay cache may be lost | < 15 min | Fail closed for authority replay until restored |
| Full region loss | 24 h logical / PITR window | < 4 h | Restore to secondary region; DNS/edge failover |
| Evidence bucket loss | Versioning/replication | < 4 h | Restore objects and verify manifests |
| Signing-key loss | 0 (key custody) | < 1 h | KMS/HSM key policy and rotation runbook |

These are design targets, not measured results. Measure them in a staging failover drill before
publishing an enterprise SLA.

## Failover drill

1. Freeze changes and record the release manifest/digests.
2. Snapshot the database and evidence object inventory.
3. Simulate API instance loss; verify LB drains and new instance passes `/readyz`.
4. Trigger managed Postgres failover; measure detection, reconnect, and write recovery.
5. Restore Redis or run in the documented fail-closed mode; verify no authority replay.
6. Restore an evidence object and verify a receipt/archive offline.
7. Simulate zone loss; promote/redirect traffic; record RTO and data loss.
8. Restore to a clean environment from backups/PITR; run RLS, smoke, and verification checks.
9. Record timings, errors, and corrective actions in `infra/releases/` or the operator DR log.

## Gaps to close

- No managed HA data tier or load balancer.
- No WAL/PITR on the live host.
- No clean-host evidence-volume restore drill.
- No tested DNS/edge failover.
- Redis replay-cache RPO/RTO not documented.
- No measured production failover or load test.

Do not claim “high availability,” “multi-AZ,” or a production SLA until these tests pass.
