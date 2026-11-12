import assert from "node:assert/strict";
import { createServer } from "node:http";
import { test } from "node:test";

import { requestTrustedTimestamp } from "../src/timestamp.js";

test("requests an RFC 3161 timestamp token", async () => {
  let body = Buffer.alloc(0);
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      body = Buffer.concat(chunks);
      res.writeHead(200, { "content-type": "application/timestamp-reply" });
      res.end(Buffer.from("timestamp-token"));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const token = await requestTrustedTimestamp(
    `http://127.0.0.1:${address.port}`,
    "canonical receipt",
  );
  assert.equal(Buffer.from(token, "base64").toString(), "timestamp-token");
  assert.equal(body[0], 0x30);
  server.close();
});
