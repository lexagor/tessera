# Analytics and Operational Polish

The Analytics page answers a small set of buyer questions rather than filling space with charts:

| Question | Surface |
|---|---|
| Is agent activity changing, and are blocked calls rising with it? | Actions over time |
| How often is policy stopping an action? | Allow / deny rate |
| Can I prove what happened? | Verified outcome percentage and outcome provenance |
| Where is the blast radius concentrated? | Risk distribution |
| How much traffic is governed by an explicit policy? | Policy coverage |
| Which agents are active, and when? | Agent activity heatmap |
| How quickly can I produce proof? | Mean time to verification (p50 / p95) |

## Data definitions

- **Verified outcome %** is the share of completed actions whose signature has been independently
  checked. `verified_at` is recorded once on the first successful check.
- **Mean time to verification** is `verified_at - created_at`, measured from the action timestamp,
  not from when someone opened the dashboard.
- **Risk distribution** uses the same tool-risk heuristic as the action tables. Denied actions are
  counted as critical.
- **Policy coverage** is the share of actions carrying a policy id. `ungoverned` is explicit.
- **Agent activity** is bucketed by UTC day and only includes the top agents by action volume.

The API endpoint is `GET /v1/analytics?range=7d|14d|30d|90d` (or `since`/`until`). The same time
range is available on the Actions page and is saved with custom views.

## Notifications and command palette

- `GET /v1/notifications` derives alerts from pending reviews, failed or unverified outcomes,
  integrations needing attention, evidence freshness, expiring keys, and shadow policies.
- `GET /v1/search?q=` searches actions, agents, policies, and verification links. The command
  palette (`⌘K` / `Ctrl+K`) adds navigation and keyboard-first navigation.
- `?` opens the shortcut sheet. `Alt+1…6` jumps to core surfaces.
- Read state is local to the browser; the underlying alerts remain derived from live data.

## Saved views

Actions can save the current filters, view, and time range in browser storage per environment.
These are intentionally local-first: they are a convenience layer, not tenant configuration.
