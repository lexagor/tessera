# Support and Service Levels

**Status:** design-partner support policy. It is not a contractual SLA unless a signed order
form says so.

## Channels

| Plan | Channel | Hours | Named contact |
|---|---|---|---|
| Design partner | Shared Slack channel + email | Business hours, Monday–Friday | Founder/engineer on call |
| Enterprise (future) | Named support + escalation rota | 24×7 for SEV-1 | Named support engineer |
| Security | `security@thetessera.xyz` | Best effort; see security targets | Security lead |

## Severity and response

| Severity | Definition | Acknowledgement | Workaround target |
|---|---|---|---|
| SEV-1 | Service unavailable, cross-tenant risk, signing failure, data loss | 1 hour business / 15 min enterprise | Continuous until contained |
| SEV-2 | Major feature unavailable, sustained errors, security concern | 4 business hours | 1 business day |
| SEV-3 | Limited impact, single integration, non-critical bug | 1 business day | 5 business days |
| SEV-4 | Question, documentation, enhancement | 2 business days | Next planned release |

Security response targets are in [`security-sla.md`](security-sla.md). Incident handling is in
[`incident-response.md`](incident-response.md).

## Escalation

1. Support engineer/ founder.
2. Incident commander for SEV-1/2.
3. Security lead for suspected data/credential impact.
4. Legal/privacy for notification decisions.

## Exclusions

No 24×7 contractual coverage, credits, uptime percentage, or recovery guarantee in the current
design-partner deployment. Those require a signed SLA, monitoring, HA, and tested DR. Do not
promise enterprise support terms before the operations exist.
