/**
 * Minimal mock of the Stripe API for local golden-path runs.
 *
 * Handles `POST /v1/charges` and `POST /v1/refunds`, echoing back the Authorization header
 * the broker attached so the harness can prove the restricted key was used.
 */
import http from "node:http";

const port = Number(process.env.MOCK_STRIPE_PORT ?? 12111);

const server = http.createServer((req, res) => {
  let body = "";
  req.on("data", (chunk) => (body += chunk));
  req.on("end", () => {
    res.setHeader("content-type", "application/json");
    const auth = req.headers.authorization ?? "";
    const rand = () => Math.random().toString(36).slice(2, 10);

    if (req.method === "POST" && req.url.startsWith("/v1/charges")) {
      res.end(
        JSON.stringify({
          id: `ch_test_${rand()}`,
          object: "charge",
          amount: 500,
          currency: "usd",
          status: "succeeded",
          _auth: auth,
        }),
      );
      return;
    }
    if (req.method === "POST" && req.url.startsWith("/v1/refunds")) {
      const params = new URLSearchParams(body);
      res.end(
        JSON.stringify({
          id: `re_test_${rand()}`,
          object: "refund",
          status: "succeeded",
          charge: params.get("charge"),
          amount: Number(params.get("amount") ?? 0),
          _auth: auth,
        }),
      );
      return;
    }
    res.statusCode = 404;
    res.end(JSON.stringify({ error: { message: `no mock route for ${req.method} ${req.url}` } }));
  });
});

server.listen(port, () => console.log(`mock-stripe listening on :${port}`));
