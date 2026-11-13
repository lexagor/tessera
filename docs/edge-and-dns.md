# Edge, WAF, and DNS

**Last updated:** 2026-11-13

The live deployment exposes Caddy on ports 80/443 and keeps the API, broker, Postgres, and
Redis off the public network. API-level rate limits and request/body limits are active. A
managed WAF/DDoS service is not deployed.

## Recommended edge

If the domain is moved behind Cloudflare (or an equivalent):

- proxy only `thetessera.xyz`, `app.thetessera.xyz`, and `verify.thetessera.xyz`;
- keep the origin IP restricted to the provider's egress ranges if possible;
- enable managed WAF rules, bot fight/Likely Automated Traffic, and a rate-limit rule for
  `/auth/*`, `/v1/*`, and `/verify/*`;
- preserve `X-Forwarded-For` and set `TRUST_PROXY=1` only for the trusted proxy;
- do not cache authenticated API responses; keep `no-store` and `Set-Cookie` intact;
- add a DDoS alert and a documented "under attack" mode.

Caddy remains the origin TLS terminator and security-header layer. Do not disable HSTS or
origin TLS verification.

## DNS

`thetessera.xyz`, `app.thetessera.xyz`, and `verify.thetessera.xyz` are live A records. The
apex is canonical. `www.thetessera.xyz` intentionally has no A record in the current
deployment; if it is added, redirect it to the apex with a 308 and keep one canonical host.
Do not add a wildcard unless staging and Auth0 callback boundaries are reviewed.

## Verification

```bash
dig +short thetessera.xyz A
dig +short app.thetessera.xyz A
dig +short verify.thetessera.xyz A
curl -sSI https://thetessera.xyz/ | sed -n '1,20p'
```

Check HSTS, CSP report-only, `x-content-type-options`, and the absence of directory listings.
A WAF is not a substitute for the broker's authorization and tenant-isolation controls.
