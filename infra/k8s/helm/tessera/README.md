# Tessera Helm chart

Deploys the Agent Action Broker. Postgres and Redis are expected as external services
(managed databases or their own charts); provide connection strings via the Secret.

```bash
kubectl create secret generic tessera-secrets \
  --from-literal=BROKER_SIGNING_KEY=0x... \
  --from-literal=DATABASE_URL=postgres://user:pass@host:5432/tessera \
  --from-literal=REDIS_URL=redis://host:6379 \
  --from-literal=TESSERA_ADMIN_TOKEN=$(openssl rand -hex 24) \
  --from-literal=TESSERA_AUTHORITY_HMAC_SECRET=$(openssl rand -hex 32)
```

To rotate the authority key without breaking in-flight tokens, add
`TESSERA_AUTHORITY_HMAC_SECRET_PREVIOUS` to the same Secret and update
`TESSERA_AUTHORITY_PREVIOUS_KID`/`TESSERA_AUTHORITY_KID` in `values.yaml`.

```bash
helm install tessera infra/k8s/helm/tessera \
  --set image.tag=0.1.3
```

The chart intentionally creates only a ClusterIP Service and no Ingress. The broker is an
internal service; expose the control-plane API through its own ingress, not the broker.
`TESSERA_PRODUCTION` and `TESSERA_DEMO_ALLOW=0` are set by default. Scrape metrics from
`/metrics`; probe liveness/readiness at `/healthz`.
