# Example: GitHub PR agent

A coding agent opens a pull request using a GitHub installation token scoped to one repository,
brokered by Tessera — instead of a long-lived personal access token.

```bash
TESSERA_ENDPOINT=http://localhost:8787 pnpm start
```

The token is short-lived and repository-scoped; a call to any other repo is denied at the broker.
