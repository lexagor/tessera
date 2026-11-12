# Demo script

Use this script for a 45–60 second silent product demo. Record at 1280×720 or larger and keep
the cursor visible.

## Setup

```bash
docker compose -f infra/docker/docker-compose.yml up --build
```

- Portal: `http://localhost:8080`
- Verifier: `http://localhost:8080/verify/`
- Site: `http://localhost:8081/`

The local stack uses dev auth and demo broker mode. Do not record real credentials, customer
names, or production data.

## Recording sequence

1. **Overview** — open the portal and show the action/verified-outcome tiles.
2. **Policy decision** — open an allowed action. Point at the authority graph and the
   **broker-observed** outcome.
3. **Human authority** — open Agent keys and show an **owner-bound** key with its delegated
   email. If the demo uses a caller-asserted key, say so explicitly.
4. **Denied action** — open a denied action and show that the credential was withheld and the
   tool call did not execute.
5. **Verification** — open a verification link. Show the chain of trust and the green signature
   result.
6. **Tamper** — click **Simulate tampering**; the verifier turns red. Click **Restore original**.
7. **Evidence** — open an evidence pack and show the reviewer report and framework coverage.

## Export

- Keep the GIF/MP4 under 15 MB.
- Save the rendered asset as `docs/assets/tessera-demo.gif` (or link the hosted MP4 from the
  README).
- Use the same asset on the landing page and in design-partner follow-ups.
- Do not commit a fabricated or edited recording; the trust chain must be from a real local run.
