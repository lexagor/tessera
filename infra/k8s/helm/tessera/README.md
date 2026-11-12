# Tessera Helm chart

Deploys the Agent Action Broker. Postgres and Redis are expected as external services
(managed databases or their own charts); provide connection strings via the Secret.

```bash
kubectl create secret generic tessera-secrets \
  --from-literal=BROKER_SIGNING_KEY=0x... \
  --from-literal=DATABASE_URL=postgres://user:pass@host:5432/tessera \
  --from-literal=REDIS_URL=redis://host:6379 \
  --from-literal=TESSERA_ADMIN_TOKEN=$(openssl rand -hex 24)

helm install tessera infra/k8s/helm/tessera \
  --set image.tag=0.6 \
  --set ingress.enabled=true --set ingress.host=tessera.example.com
```

`TESSERA_DEMO_ALLOW` defaults to `"0"` (auth required). Set it to `"1"` only for demos.
Scrape metrics from `/metrics`; probe liveness/readiness at `/healthz`.
