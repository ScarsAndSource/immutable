/**
 * _shared/crypto.ts — shared cryptographic helpers for all Edge Functions.
 *
 * Import with:
 *   import { sha256Hex, verifySig, signBytes, taggedData, canon } from "../_shared/crypto.ts";
 */

import { ed25519 } from "https://esm.sh/@noble/curves@1.4.0/ed25519";
import { hex } from "https://esm.sh/@scure/base@1.1.7";

export const DOMAIN_PREFIX = new TextEncoder().encode("immutable/v1/");

export function serverMs(): bigint {
  return BigInt(Date.now());
}

export function taggedData(domain: string, data: Uint8Array): Uint8Array {
  const domainBytes = new TextEncoder().encode(domain + "\x00");
  const out = new Uint8Array(DOMAIN_PREFIX.length + domainBytes.length + data.length);
  out.set(DOMAIN_PREFIX, 0);
  out.set(domainBytes, DOMAIN_PREFIX.length);
  out.set(data, DOMAIN_PREFIX.length + domainBytes.length);
  return out;
}

export async function sha256Hex(data: Uint8Array): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

export function verifySig(
  pubHex: string, domain: string, data: Uint8Array, sigHex: string,
): boolean {
  try {
    return ed25519.verify(hex.decode(sigHex), taggedData(domain, data), hex.decode(pubHex));
  } catch {
    return false;
  }
}

export function signBytes(domain: string, data: Uint8Array, seedHex: string): string {
  return hex.encode(ed25519.sign(taggedData(domain, data), hex.decode(seedHex)));
}

/** Canonical JSON: sorted keys (code-point order), ASCII-only keys in v2 documents. */
export function canon(obj: unknown): Uint8Array {
  function sortedKeys(o: unknown): unknown {
    if (Array.isArray(o)) return o.map(sortedKeys);
    if (o !== null && typeof o === "object") {
      const sorted: Record<string, unknown> = {};
      for (const k of Object.keys(o as object).sort()) {
        sorted[k] = sortedKeys((o as Record<string, unknown>)[k]);
      }
      return sorted;
    }
    return o;
  }
  return new TextEncoder().encode(JSON.stringify(sortedKeys(obj)));
}

export function isHex64(s: unknown): s is string {
  return typeof s === "string" && /^[0-9a-f]{64}$/.test(s);
}

export function isId(s: unknown): s is string {
  return typeof s === "string" && /^[A-Za-z0-9._\-]{1,64}$/.test(s);
}

export function errResponse(status: number, code: string, detail: unknown = ""): Response {
  return new Response(JSON.stringify({ error: code, detail }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export function okResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}
