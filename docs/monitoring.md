# Monitoring Configuration

The repository includes Prometheus scrape/alert rules and a Grafana dashboard. No external
monitoring account is configured in this repository.

## Files

- `infra/observability/prometheus.yml` — API/broker scrape and blackbox readiness probe.
- `infra/observability/alerts.yml` — API/broker alert rules.
- `infra/observability/grafana-dashboard.json` — request, error, latency, rate-limit, webhook,
  and readiness panels.
- `infra/scripts/host-health.sh` — host-level readiness, backup freshness, RLS, and container
  checks that can run from cron.

## Deploy

Use a managed Prometheus/Grafana stack or a dedicated monitoring host. Keep the API/broker
scrape targets private; only the blackbox probe should reach the public endpoint. Add the
Alertmanager receiver (email/Slack/PagerDuty) as an operator secret; do not commit it.

```bash
# On the monitoring host, with the repository copied:
prometheus --config.file=infra/observability/prometheus.yml
# Import infra/observability/grafana-dashboard.json into Grafana.
```

Install the host checks under `/opt/tessera/infra/scripts` and run them from cron and route its nonzero exit through the
monitoring agent. Example:

```bash
*/15 * * * * root /opt/tessera/infra/scripts/host-health.sh >> /var/log/tessera-host-health.log 2>&1
```

## Required alerts

At minimum: API/broker down, 5xx rate, readiness failing, backup stale, disk >85%, certificate
expiry, and proof-link failure. The proof-link check is already in `.github/workflows/proof.yml`;
the uptime check is in `.github/workflows/uptime.yml`.

## Current limitation

The live VPS is a single 2 GB host. Do not run a full Prometheus/Grafana/Alertmanager stack on it
without measuring memory; scrape from a separate monitoring host or use a managed service.
