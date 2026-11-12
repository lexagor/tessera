const counters = {
  requests: 0,
  errors: 0,
  rateLimited: 0,
  webhookDelivered: 0,
  webhookFailed: 0,
  durationMs: 0,
};

const startedAt = Date.now();

export function recordRequest(status: number, durationMs: number): void {
  counters.requests += 1;
  counters.durationMs += durationMs;
  if (status >= 500) counters.errors += 1;
}

export function recordRateLimited(): void {
  counters.rateLimited += 1;
}

export function recordWebhookDelivered(): void {
  counters.webhookDelivered += 1;
}

export function recordWebhookFailed(): void {
  counters.webhookFailed += 1;
}

export function renderMetrics(): string {
  return [
    "# HELP tessera_api_requests_total API requests",
    "# TYPE tessera_api_requests_total counter",
    `tessera_api_requests_total ${counters.requests}`,
    "# HELP tessera_api_errors_total API responses with status >= 500",
    "# TYPE tessera_api_errors_total counter",
    `tessera_api_errors_total ${counters.errors}`,
    "# HELP tessera_api_rate_limited_total Requests rejected by rate limits",
    "# TYPE tessera_api_rate_limited_total counter",
    `tessera_api_rate_limited_total ${counters.rateLimited}`,
    "# HELP tessera_api_webhook_delivered_total Webhook deliveries marked delivered",
    "# TYPE tessera_api_webhook_delivered_total counter",
    `tessera_api_webhook_delivered_total ${counters.webhookDelivered}`,
    "# HELP tessera_api_webhook_failed_total Webhook delivery failures",
    "# TYPE tessera_api_webhook_failed_total counter",
    `tessera_api_webhook_failed_total ${counters.webhookFailed}`,
    "# HELP tessera_api_request_duration_seconds_sum Total request duration",
    "# TYPE tessera_api_request_duration_seconds_sum counter",
    `tessera_api_request_duration_seconds_sum ${(counters.durationMs / 1000).toFixed(6)}`,
    "# HELP tessera_api_request_duration_seconds_count Request count for duration average",
    "# TYPE tessera_api_request_duration_seconds_count counter",
    `tessera_api_request_duration_seconds_count ${counters.requests}`,
    "# HELP tessera_api_uptime_seconds Process uptime",
    "# TYPE tessera_api_uptime_seconds gauge",
    "# TYPE tessera_api_uptime_seconds gauge",
    `tessera_api_uptime_seconds ${Math.floor((Date.now() - startedAt) / 1000)}`,
    "",
  ].join("\n");
}
