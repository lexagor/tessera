import { createHash, randomBytes } from "node:crypto";

function length(value: number): Buffer {
  if (value < 0x80) return Buffer.from([value]);
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32BE(value);
  let start = 0;
  while (start < 3 && bytes[start] === 0) start += 1;
  const body = bytes.subarray(start);
  return Buffer.from([0x80 | body.length, ...body]);
}

function der(tag: number, value: Uint8Array): Buffer {
  return Buffer.concat([Buffer.from([tag]), length(value.length), Buffer.from(value)]);
}

function integer(value: bigint): Buffer {
  let hex = value.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  let body = Buffer.from(hex, "hex");
  if (body[0]! & 0x80) body = Buffer.concat([Buffer.from([0]), body]);
  return der(0x02, body);
}

function oidSha256(): Buffer {
  return der(0x06, Buffer.from("608648016503040201", "hex"));
}

function timestampRequest(digest: Buffer, nonce: bigint): Buffer {
  const messageImprint = der(
    0x30,
    Buffer.concat([der(0x30, Buffer.concat([oidSha256(), der(0x05, Buffer.alloc(0))])), der(0x04, digest)]),
  );
  return der(
    0x30,
    Buffer.concat([integer(1n), messageImprint, integer(nonce), der(0x01, Buffer.from([0xff]))]),
  );
}

/**
 * Request an RFC 3161 timestamp for the canonical bytes of an Agent Receipt. The returned
 * value is the base64-encoded DER TimeStampToken to place in `action.trusted_timestamp`.
 */
export async function requestTrustedTimestamp(
  tsaUrl: string,
  canonicalPayload: string | Uint8Array,
): Promise<string> {
  const digest = createHash("sha256").update(canonicalPayload).digest();
  const nonce = BigInt(`0x${randomBytes(8).toString("hex")}`);
  const request = timestampRequest(digest, nonce);
  const response = await fetch(tsaUrl, {
    method: "POST",
    headers: {
      "content-type": "application/timestamp-query",
      accept: "application/timestamp-reply",
    },
    body: request,
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) {
    throw new Error(`TSA returned ${response.status}`);
  }
  return Buffer.from(await response.arrayBuffer()).toString("base64");
}
