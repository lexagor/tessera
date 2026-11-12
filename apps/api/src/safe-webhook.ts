import { lookup } from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import { isIP } from "node:net";

import { env, isProduction } from "./env.js";

const MAX_RESPONSE_BYTES = 64 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;

function isPrivateIpv4(address: string): boolean {
  const octets = address.split(".").map(Number);
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return true;
  }
  const [a, b] = octets as [number, number, number, number];
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && Number(octets[2]) === 100) ||
    (a === 203 && b === 0 && Number(octets[2]) === 113) ||
    a >= 224
  );
}

function mappedIpv4(address: string): string | null {
  const lower = address.toLowerCase();
  if (!lower.startsWith("::ffff:")) return null;
  const tail = lower.slice("::ffff:".length);
  if (isIP(tail) === 4) return tail;
  const parts = tail.split(":");
  if (parts.length !== 2) return null;
  const high = Number.parseInt(parts[0] ?? "", 16);
  const low = Number.parseInt(parts[1] ?? "", 16);
  if (!Number.isInteger(high) || !Number.isInteger(low) || high > 0xffff || low > 0xffff) {
    return null;
  }
  return `${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}`;
}

/** True for loopback, private, link-local, metadata, documentation, multicast, or invalid IPs. */
export function isPrivateAddress(address: string): boolean {
  const version = isIP(address);
  if (version === 4) return isPrivateIpv4(address);
  if (version !== 6) return true;

  const lower = address.toLowerCase();
  const mapped = mappedIpv4(lower);
  if (mapped) return isPrivateIpv4(mapped);

  return (
    lower === "::" ||
    lower === "::1" ||
    lower.startsWith("fe80:") ||
    lower.startsWith("fc") ||
    lower.startsWith("fd") ||
    lower.startsWith("ff") ||
    lower.startsWith("2001:db8:")
  );
}

export function isPrivateHostname(hostname: string): boolean {
  const host = hostname.trim().toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (!host || host === "localhost" || host.endsWith(".localhost")) return true;
  if (host.endsWith(".local") || host.endsWith(".internal")) return true;
  if (isIP(host)) return isPrivateAddress(host);
  return false;
}

async function pinnedAddress(url: URL): Promise<{ address: string; family: 4 | 6 }> {
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (isIP(host)) {
    const family = isIP(host) as 4 | 6;
    if (!env.ALLOW_PRIVATE_WEBHOOKS && isPrivateAddress(host)) {
      throw new Error("Webhook destination resolves to a private or reserved address");
    }
    return { address: host, family };
  }

  const records = await lookup(host, { all: true, verbatim: true });
  if (records.length === 0) throw new Error("Webhook destination did not resolve");
  if (!env.ALLOW_PRIVATE_WEBHOOKS) {
    for (const record of records) {
      if (isPrivateAddress(record.address)) {
        throw new Error("Webhook destination resolves to a private or reserved address");
      }
    }
  }
  const selected = records[0];
  if (!selected) throw new Error("Webhook destination did not resolve");
  return { address: selected.address, family: selected.family === 6 ? 6 : 4 };
}

export interface SafeWebhookResponse {
  status: number;
}

/** POST JSON without redirects, DNS rebinding, private targets, or unbounded response reads. */
export async function safeWebhookPost(input: {
  url: string;
  headers: Record<string, string>;
  body: string;
  timeoutMs?: number;
}): Promise<SafeWebhookResponse> {
  const url = new URL(input.url);
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("Webhook URL must use http or https");
  }
  if (isProduction && url.protocol !== "https:") {
    throw new Error("Webhook URL must use https in production");
  }
  if (url.username || url.password) throw new Error("Webhook URL must not contain credentials");
  if (!env.ALLOW_PRIVATE_WEBHOOKS && isPrivateHostname(url.hostname)) {
    throw new Error("Private webhook hosts are not allowed");
  }

  const target = await pinnedAddress(url);
  const timeoutMs = input.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const transport = url.protocol === "https:" ? https : http;

  return await new Promise<SafeWebhookResponse>((resolve, reject) => {
    let settled = false;
    const finish = (error: Error | null, status?: number) => {
      if (settled) return;
      settled = true;
      if (error) reject(error);
      else resolve({ status: status ?? 0 });
    };

    const request = transport.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port || undefined,
        path: `${url.pathname}${url.search}`,
        method: "POST",
        headers: { ...input.headers, host: url.host },
        timeout: timeoutMs,
        servername: url.protocol === "https:" ? url.hostname : undefined,
        lookup: ((_hostname: string, options: { all?: boolean }, callback: Function) => {
          if (options.all) {
            callback(null, [{ address: target.address, family: target.family }]);
          } else {
            callback(null, target.address, target.family);
          }
        }) as never,
      },
      (response) => {
        const status = response.statusCode ?? 0;
        if (status >= 300 && status < 400) {
          response.resume();
          finish(new Error("Webhook redirects are not allowed"));
          return;
        }
        if (status < 200 || status >= 300) {
          response.resume();
          finish(new Error(`Webhook endpoint returned ${status}`));
          return;
        }
        let bytes = 0;
        response.on("data", (chunk: Buffer) => {
          bytes += chunk.length;
          if (bytes > MAX_RESPONSE_BYTES) {
            response.destroy();
            finish(new Error("Webhook response exceeded the size limit"));
          }
        });
        response.on("end", () => finish(null, status));
        response.on("error", (error) => finish(error));
      },
    );

    request.on("timeout", () => request.destroy(new Error("Webhook request timed out")));
    request.on("error", (error) => finish(error));
    request.end(input.body);
  });
}
