/**
 * heartbeat/index.ts — POST /v1/ping
 *
 * Receives a seat-key-signed heartbeat, verifies it, records it, and returns
 * the current server time plus outage budget state.
 *
 * Ping format (FORMAT_V1 §12 / FORMAT_V2 §8):
 *   Canonical {v, exam_id, session_id, ws_id, boot_id, boot_ns, last_seq}
 *   signed with the seat key, domain "ping".
 *
 * Rules:
 *   • boot_ns must increase within a boot_id (anti-replay).
 *   • The session must be open (not finalized) and within the drain window.
 *   • If the session is past grace_expired, the ping returns 410 FINALIZED.
 *   • A ping closes any open outage and updates the budget.
 *   • Response: {server_ms, remaining_ms, held_upto} — never 4xx except auth/window errors.
 *
 * Ref: FORMAT_V2.md §§ 8, 10.
 */

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { ed25519 } from "https://esm.sh/@noble/curves@1.4.0/ed25519";
import { hex } from "https://esm.sh/@scure/base@1.1.7";

// ---------------------------------------------------------------------------
// Helpers (identical to ingest/index.ts – in a real monorepo these live in
// supabase/functions/_shared/crypto.ts and are imported relatively)
// ---------------------------------------------------------------------------
const PREFIX = new TextEncoder().encode("immutable/v1/");

function serverMs(): bigint {
  return BigInt(Date.now());
}

function taggedData(domain: string, data: Uint8Array): Uint8Array {
  const domainBytes = new TextEncoder().encode(domain + "\x00");
  const out = new Uint8Array(PREFIX.length + domainBytes.length + data.length);
  out.set(PREFIX, 0);
  out.set(domainBytes, PREFIX.length);
  out.set(data, PREFIX.length + domainBytes.length);
  return out;
}

function verifySig(pubHex: string, domain: string, data: Uint8Array, sigHex: string): boolean {
  try {
    const pub = hex.decode(pubHex);
    const sig = hex.decode(sigHex);
    return ed25519.verify(sig, taggedData(domain, data), pub);
  } catch {
    return false;
  }
}

function err(status: number, code: string, detail = ""): Response {
  return new Response(JSON.stringify({ error: code, detail }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function ok(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function supabase() {
  return createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  );
}

// ---------------------------------------------------------------------------
// Outage accounting (FORMAT_V2 §10)
// Returns remaining_ms given the session row and active config.
// ---------------------------------------------------------------------------
function computeRemainingMs(session: {
  t_last_contact_ms: number;
  outage_used_ms: number;
  outage_count: number;
}, cfg: {
  outage_threshold_ms: number;
  outage_cap_ms: number;
  outage_total_ms: number;
  end_ms: number;
  drain_ms: number;
}, now: bigint): number {
  const t = Number(now);
  const gap = t - session.t_last_contact_ms;
  // If currently in an open outage, count its impact
  let currentOutage = 0;
  if (gap > cfg.outage_threshold_ms) {
    currentOutage = Math.min(gap - cfg.outage_threshold_ms, cfg.outage_cap_ms);
  }
  const used = session.outage_used_ms + currentOutage;
  return Math.max(0, cfg.outage_total_ms - used);
}

// Close an open outage: compute counted_ms and update outage_used_ms.
// Returns the gap record for journaling.
function closeOutage(session: {
  t_last_contact_ms: number;
  outage_used_ms: number;
  outage_count: number;
}, cfg: {
  outage_threshold_ms: number;
  outage_cap_ms: number;
  outage_total_ms: number;
}, now: bigint): { hadOutage: boolean; grossMs: number; countedMs: number } {
  const t = Number(now);
  const grossMs = t - session.t_last_contact_ms;
  if (grossMs <= cfg.outage_threshold_ms) {
    return { hadOutage: false, grossMs, countedMs: 0 };
  }
  const countedMs = Math.min(grossMs - cfg.outage_threshold_ms, cfg.outage_cap_ms);
  return { hadOutage: true, grossMs, countedMs };
}

// ---------------------------------------------------------------------------
// POST /v1/ping handler
// ---------------------------------------------------------------------------
async function handlePing(req: Request): Promise<Response> {
  const raw = new Uint8Array(await req.arrayBuffer());
  if (raw.length > 4096) return err(413, "TOO_LARGE");

  let doc: Record<string, unknown>;
  try {
    doc = JSON.parse(new TextDecoder().decode(raw)) as Record<string, unknown>;
  } catch {
    return err(400, "BAD_JSON");
  }

  // Required fields from v1 §12 ping structure
  const { v, exam_id, session_id, ws_id, boot_id, boot_ns, last_seq, sig } =
    doc as Record<string, unknown>;

  if (v !== 1 || !exam_id || !session_id || !ws_id || !boot_id ||
      typeof boot_ns !== "number" || typeof last_seq !== "number" || !sig) {
    return err(400, "MISSING_FIELDS");
  }

  const db = supabase();

  // Load session
  const { data: session } = await db
    .from("sessions")
    .select("*")
    .eq("exam_id", exam_id)
    .eq("session_id", session_id)
    .eq("ws_id", ws_id)
    .single();

  if (!session) return err(404, "SESSION_NOT_FOUND");
  if (session.finalized_at_ms) return err(410, "FINALIZED");

  // Load active config
  const { data: cfg } = await db
    .from("active_configs")
    .select("*")
    .eq("exam_id", exam_id)
    .single();
  if (!cfg) return err(404, "NO_CONFIG");

  const now = serverMs();

  // Drain window check
  if (Number(now) > cfg.end_ms + cfg.drain_ms) {
    return err(403, "OUTSIDE_WINDOW", "drain window has closed");
  }

  // Verify seat-key signature over raw ping bytes
  // The signature covers the body without the sig field
  const bodyOnly = { v, exam_id, session_id, ws_id, boot_id, boot_ns, last_seq };
  const bodyKeys = Object.keys(bodyOnly).sort() as (keyof typeof bodyOnly)[];
  const sorted: Record<string, unknown> = {};
  for (const k of bodyKeys) sorted[k] = bodyOnly[k];
  const bodyBytes = new TextEncoder().encode(JSON.stringify(sorted));

  if (!verifySig(session.seat_pub, "ping", bodyBytes, sig as string)) {
    return err(403, "BAD_SIGNATURE");
  }

  // Anti-replay: boot_ns must increase within the same boot_id
  const { data: lastPing } = await db
    .from("pings")
    .select("boot_id, boot_ns")
    .eq("exam_id", exam_id)
    .eq("session_id", session_id)
    .eq("ws_id", ws_id)
    .order("server_ms", { ascending: false })
    .limit(1)
    .single();

  if (lastPing) {
    if (lastPing.boot_id === boot_id && (boot_ns as number) <= lastPing.boot_ns) {
      return err(409, "REPLAY", "boot_ns must increase within a boot_id");
    }
  }

  // Close open outage if any; compute updated budget
  const { hadOutage, grossMs, countedMs } = closeOutage(session, cfg, now);

  const newOutageUsed = session.outage_used_ms + countedMs;
  const newOutageCount = session.outage_count + (hadOutage ? 1 : 0);

  // Record ping
  await db.from("pings").insert({
    exam_id, session_id, ws_id,
    boot_id,
    boot_ns,
    last_seq,
    server_ms: Number(now),
  }).throwOnError();

  // Update outage budget in session (trigger will also advance t_last_contact_ms)
  if (hadOutage) {
    await db.from("sessions")
      .update({
        outage_used_ms: newOutageUsed,
        outage_count: newOutageCount,
      })
      .eq("exam_id", exam_id)
      .eq("session_id", session_id)
      .eq("ws_id", ws_id)
      .throwOnError();

    // Journal the closed outage
    const { data: lastJournal } = await db
      .from("journal")
      .select("seq, entry_hash")
      .eq("exam_id", exam_id)
      .eq("session_id", session_id)
      .eq("ws_id", ws_id)
      .order("seq", { ascending: false })
      .limit(1)
      .single();

    const prevHash = lastJournal?.entry_hash ?? "0".repeat(64);
    const nextSeq = (lastJournal?.seq ?? -1) + 1;
    const entryBody = {
      kind: "CONTACT_GAP", gross_ms: grossMs,
      subtracted_ms: 0, counted_ms: countedMs,
    };
    const entryBytes = new TextEncoder().encode(JSON.stringify(entryBody) + prevHash + String(nextSeq));
    const entryHash = await crypto.subtle.digest("SHA-256", entryBytes)
      .then(b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, "0")).join(""));

    await db.from("journal").insert({
      exam_id, session_id, ws_id,
      seq: nextSeq,
      kind: "CONTACT_GAP",
      body_json: entryBody,
      prev_hash: prevHash,
      entry_hash: entryHash,
    }).throwOnError();
  }

  const remainingMs = Math.max(0, cfg.outage_total_ms - newOutageUsed);

  return ok({
    server_ms: Number(now),
    remaining_ms: remainingMs,
    held_upto: session.held_upto,
  });
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------
Deno.serve(async (req: Request) => {
  const url = new URL(req.url);
  try {
    if (req.method === "POST" && url.pathname === "/v1/ping") {
      return await handlePing(req);
    }
    return new Response(JSON.stringify({ error: "NOT_FOUND" }), {
      status: 404,
      headers: { "Content-Type": "application/json" },
    });
  } catch (e) {
    console.error("heartbeat error", e);
    return new Response(JSON.stringify({ error: "INTERNAL" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
});
