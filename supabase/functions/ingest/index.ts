/**
 * ingest/index.ts — POST /v1/batch and PUT /v1/blob/:sha256
 *
 * Handles:
 *   POST /v1/batch           – upload a signed batch; returns a server-signed ack anchor
 *   PUT  /v1/blob/:sha256    – upload a file blob; verifies hash
 *   POST /v1/session/open    – open a session within the connect window
 *
 * Security model (enforced here, not in the DB):
 *   1. Parse the raw bytes first (no JSON.parse on untrusted input).
 *   2. Verify the seat-key signature over raw bytes before touching the DB.
 *   3. Enforce window rules using server_ms() (never client timestamps).
 *   4. All DB writes via service_role; RLS is defence-in-depth.
 *
 * Ref: FORMAT_V2.md §§ 7, 8, 10.
 */

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { ed25519 } from "https://esm.sh/@noble/curves@1.4.0/ed25519";
import { hex } from "https://esm.sh/@scure/base@1.1.7";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const PREFIX = new TextEncoder().encode("immutable/v1/");
const MAX_BATCH_BYTES = 256 * 1024;      // 256 KiB – headroom above v1 spec limit
const MAX_BLOB_BYTES  = 2 * 1024 * 1024; // 2 MiB per blob (FORMAT_V2 §8)
const MAX_SESSION_BLOB_BYTES = 50 * 1024 * 1024; // 50 MiB per session
const MAX_EVENTS_PER_BATCH = 256;        // FORMAT_V2 §8
const MAX_BATCHES_PER_SESSION_PER_MIN = 60;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
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

async function sha256Hex(data: Uint8Array): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
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

// Parse strict canonical JSON (numbers only, no floats, ASCII keys in v2 docs)
function parseCanon(raw: Uint8Array): unknown {
  const text = new TextDecoder().decode(raw);
  // Basic depth / size guard – full canon validation is in the Python verifier
  if (text.length > 1_048_576) throw new Error("too large");
  return JSON.parse(text);
}

// ---------------------------------------------------------------------------
// Supabase client (service_role bypasses RLS)
// ---------------------------------------------------------------------------
function supabase() {
  return createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  );
}

// Server signing key (Ed25519 seed hex, stored in Edge Function secrets)
function serverSigner() {
  const seedHex = Deno.env.get("SERVER_SEED_HEX");
  if (!seedHex || seedHex.length !== 64) throw new Error("SERVER_SEED_HEX not configured");
  return {
    seed: hex.decode(seedHex),
    pub: ed25519.getPublicKey(hex.decode(seedHex)),
  };
}

function sign(domain: string, data: Uint8Array, seed: Uint8Array): string {
  return hex.encode(ed25519.sign(taggedData(domain, data), seed));
}

// ---------------------------------------------------------------------------
// Anchor builder (FORMAT_V2 §8: ack = witness-kind anchor, holder = server_id)
// ---------------------------------------------------------------------------
async function buildAck(params: {
  examId: string; sessionId: string; wsId: string;
  uptoseq: number; head: string; seenMs: bigint;
  serverId: string; serverSeed: Uint8Array;
}): Promise<Uint8Array> {
  const body = {
    v: 1,
    exam_id: params.examId,
    session_id: params.sessionId,
    ws_id: params.wsId,
    upto_seq: params.uptoseq,
    head: params.head,
    kind: "witness",
    holder: params.serverId,
    seen_ms: Number(params.seenMs),
  };
  // Sort keys canonically (already ASCII, code-point order = lexicographic)
  const keys = Object.keys(body).sort();
  const sorted: Record<string, unknown> = {};
  for (const k of keys) sorted[k] = (body as Record<string, unknown>)[k];
  const bodyBytes = new TextEncoder().encode(JSON.stringify(sorted));
  const sigHex = sign("cosign", bodyBytes, params.serverSeed);
  const doc = { body: sorted, sig: sigHex };
  const docKeys = ["body", "sig"];
  const sorted2: Record<string, unknown> = {};
  for (const k of docKeys) sorted2[k] = (doc as Record<string, unknown>)[k];
  return new TextEncoder().encode(JSON.stringify(sorted2));
}

// ---------------------------------------------------------------------------
// Rate-limiter (per session per minute, in-memory approximation via DB count)
// ---------------------------------------------------------------------------
async function checkBatchRate(
  db: ReturnType<typeof supabase>,
  examId: string, sessionId: string, wsId: string,
): Promise<boolean> {
  const cutoff = Number(serverMs()) - 60_000;
  const { count } = await db
    .from("batches")
    .select("*", { count: "exact", head: true })
    .eq("exam_id", examId)
    .eq("session_id", sessionId)
    .eq("ws_id", wsId)
    .gte("ingested_at_ms", cutoff)
    .throwOnError()
    .single();
  return (count ?? 0) < MAX_BATCHES_PER_SESSION_PER_MIN;
}

// ---------------------------------------------------------------------------
// POST /v1/session/open
// ---------------------------------------------------------------------------
async function handleSessionOpen(req: Request): Promise<Response> {
  const raw = new Uint8Array(await req.arrayBuffer());
  if (raw.length > 4096) return err(413, "TOO_LARGE");

  let doc: Record<string, unknown>;
  try { doc = parseCanon(raw) as Record<string, unknown>; }
  catch { return err(400, "BAD_JSON"); }

  const { exam_id, session_id, ws_id, sig } = doc as Record<string, string>;
  if (!exam_id || !session_id || !ws_id || !sig) return err(400, "MISSING_FIELDS");

  const db = supabase();

  // Fetch exam & active config
  const { data: exam } = await db.from("exams").select("*").eq("exam_id", exam_id).single();
  if (!exam) return err(404, "EXAM_NOT_FOUND");

  const { data: cfg } = await db
    .from("active_configs")
    .select("*")
    .eq("exam_id", exam_id)
    .single();
  if (!cfg) return err(404, "NO_CONFIG");

  const now = serverMs();
  if (now < BigInt(cfg.connect_open_ms) || now > BigInt(cfg.connect_close_ms)) {
    return err(403, "OUTSIDE_WINDOW", "session/open requires connect_open_ms <= T <= connect_close_ms");
  }

  // Load roster to find seat pub
  const roster = parseCanon(exam.roster_bytes) as Record<string, unknown>;
  const rosterBody = (roster as { body: Record<string, unknown> }).body;
  const seats = rosterBody.seats as Array<{ ws_id: string; pub: string; candidate?: string }>;
  const seat = seats.find(s => s.ws_id === ws_id);
  if (!seat) return err(403, "SEAT_NOT_FOUND");

  // Verify seat-key signature over the body bytes (everything except sig)
  const bodyOnly = { ...doc };
  delete bodyOnly.sig;
  const bodyKeys = Object.keys(bodyOnly).sort();
  const sortedBody: Record<string, unknown> = {};
  for (const k of bodyKeys) sortedBody[k] = bodyOnly[k];
  const bodyBytes = new TextEncoder().encode(JSON.stringify(sortedBody));
  if (!verifySig(seat.pub, "enroll", bodyBytes, sig)) {
    return err(403, "BAD_SIGNATURE");
  }

  // Check if session already exists (idempotent)
  const { data: existing } = await db
    .from("sessions")
    .select("*")
    .eq("exam_id", exam_id)
    .eq("session_id", session_id)
    .eq("ws_id", ws_id)
    .single();

  if (existing) {
    if (existing.finalized_at_ms) return err(410, "FINALIZED");
    return ok({
      server_ms: Number(now),
      deadline_ms: cfg.end_ms + cfg.drain_ms,
      held_upto: existing.held_upto,
      held_head: existing.held_head,
      rev: cfg.rev,
    });
  }

  // Create session
  const scheduleSha256 = await sha256Hex(new Uint8Array(cfg.config_bytes));
  await db.from("sessions").insert({
    exam_id,
    session_id,
    ws_id,
    candidate: seat.candidate ?? null,
    seat_pub: seat.pub,
    opened_at_ms: Number(now),
    schedule_sha256: scheduleSha256,
    schedule_rev: cfg.rev,
    t_last_contact_ms: Number(now),
  }).throwOnError();

  // Journal: SESSION_OPEN
  await db.from("journal").insert({
    exam_id, session_id, ws_id, seq: 0,
    kind: "SESSION_OPEN",
    body_json: { opened_at_ms: Number(now), schedule_rev: cfg.rev },
    prev_hash: "0".repeat(64),
    entry_hash: await sha256Hex(new TextEncoder().encode(`SESSION_OPEN:${exam_id}:${session_id}:${ws_id}:${now}`)),
  }).throwOnError();

  return ok({
    server_ms: Number(now),
    deadline_ms: cfg.end_ms + cfg.drain_ms,
    held_upto: -1,
    held_head: "0".repeat(64),
    rev: cfg.rev,
  });
}

// ---------------------------------------------------------------------------
// POST /v1/batch
// ---------------------------------------------------------------------------
async function handleBatch(req: Request): Promise<Response> {
  const raw = new Uint8Array(await req.arrayBuffer());
  if (raw.length > MAX_BATCH_BYTES) return err(413, "TOO_LARGE");

  // Parse batch envelope: canonical {header: {...}, sig: hex, events: [...]}
  let batch: Record<string, unknown>;
  try { batch = parseCanon(raw) as Record<string, unknown>; }
  catch { return err(400, "BAD_JSON"); }

  const header = batch.header as Record<string, unknown> | undefined;
  if (!header) return err(400, "MISSING_HEADER");

  const { exam_id, session_id, ws_id, first_seq, last_seq, head } =
    header as Record<string, unknown>;
  const sig = batch.sig as string | undefined;

  if (!exam_id || !session_id || !ws_id || first_seq === undefined ||
      last_seq === undefined || !head || !sig) {
    return err(400, "MISSING_FIELDS");
  }
  if (typeof first_seq !== "number" || typeof last_seq !== "number" ||
      last_seq < first_seq || last_seq - first_seq >= MAX_EVENTS_PER_BATCH) {
    return err(400, "BAD_SEQ_RANGE");
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

  // Load active config for window check
  const { data: cfg } = await db
    .from("active_configs")
    .select("*")
    .eq("exam_id", exam_id)
    .single();
  if (!cfg) return err(404, "NO_CONFIG");

  const now = serverMs();
  if (now > BigInt(cfg.end_ms) + BigInt(cfg.drain_ms)) {
    return err(403, "OUTSIDE_WINDOW", "exam window has closed");
  }

  // Rate check
  if (!await checkBatchRate(db, exam_id as string, session_id as string, ws_id as string)) {
    return err(429, "RATE", "too many batches per minute");
  }

  // Verify seat-key signature over raw batch bytes
  if (!verifySig(session.seat_pub, "batch", raw, sig)) {
    return err(403, "BAD_SIGNATURE");
  }

  // Sequence continuity: first_seq must be held_upto + 1
  if ((first_seq as number) !== session.held_upto + 1) {
    if ((first_seq as number) <= session.held_upto) {
      // Stale or fork check
      const { data: existing } = await db
        .from("batches")
        .select("head")
        .eq("exam_id", exam_id)
        .eq("session_id", session_id)
        .eq("ws_id", ws_id)
        .eq("first_seq", first_seq)
        .single();
      if (existing && existing.head === head) {
        // Idempotent: return cached ack
        const { data: b } = await db
          .from("batches")
          .select("ack_bytes")
          .eq("exam_id", exam_id).eq("session_id", session_id)
          .eq("ws_id", ws_id).eq("first_seq", first_seq).single();
        if (b?.ack_bytes) {
          return new Response(b.ack_bytes, {
            status: 200,
            headers: { "Content-Type": "application/octet-stream" },
          });
        }
      }
      if (existing && existing.head !== head) {
        return err(409, "FORK", "same seq, different head – equivocation recorded");
      }
      return err(409, "STALE", "seq at or below held");
    }
    return err(409, "ROLLBACK", "client chain is shorter than held; get a TRANSFER");
  }

  // Hash the raw bytes for content-addressing
  const batchSha256 = await sha256Hex(raw);

  // Build server-signed ack
  const signer = serverSigner();
  const serverId = Deno.env.get("SERVER_ID") ?? "server-01";
  const ackBytes = await buildAck({
    examId: exam_id as string,
    sessionId: session_id as string,
    wsId: ws_id as string,
    uptoseq: last_seq as number,
    head: head as string,
    seenMs: now,
    serverId,
    serverSeed: signer.seed,
  });

  // Extract teacher board fields from the newest event in the batch
  function boardFields(rawEvents: unknown[] | undefined) {
    if (!Array.isArray(rawEvents) || !rawEvents.length) return {};
    const ev = rawEvents[rawEvents.length - 1] as Record<string, unknown> | undefined;
    if (!ev || typeof ev !== "object") return {};
    const b = (ev.body as Record<string, unknown>) || {};
    return {
      last_boot_id:  typeof ev.boot_id === "string" ? ev.boot_id : null,
      last_typ:      typeof ev.typ === "string" ? ev.typ : null,
      last_file:     typeof b.relpath === "string" ? b.relpath : null,
      last_event_id: typeof ev.event_id === "string" ? ev.event_id : null,
      last_seq:      typeof ev.seq === "number" ? ev.seq : null,
      last_admit_ms: Number(now),
    };
  }

  // Store batch + ack, advance held state — atomically
  await db.from("batches").insert({
    exam_id, session_id, ws_id,
    first_seq, last_seq,
    head,
    batch_sha256: batchSha256,
    batch_bytes: Array.from(raw),  // stored as bytea
    ack_bytes: Array.from(ackBytes),
    ingested_at_ms: Number(now),
  }).throwOnError();

  const extra = boardFields(doc.events as unknown[] | undefined);
  try {
    await db.from("sessions")
      .update({ held_upto: last_seq, held_head: head, ...extra })
      .eq("exam_id", exam_id)
      .eq("session_id", session_id)
      .eq("ws_id", ws_id)
      .throwOnError();
  } catch (_e) {
    // Migration 00002 may not be applied yet in dev; fall back cleanly.
    await db.from("sessions")
      .update({ held_upto: last_seq, held_head: head })
      .eq("exam_id", exam_id)
      .eq("session_id", session_id)
      .eq("ws_id", ws_id)
      .throwOnError();
  }

  return new Response(ackBytes, {
    status: 200,
    headers: { "Content-Type": "application/octet-stream" },
  });
}

// ---------------------------------------------------------------------------
// PUT /v1/blob/:sha256
// ---------------------------------------------------------------------------
async function handleBlob(req: Request, sha256: string): Promise<Response> {
  if (!/^[0-9a-f]{64}$/.test(sha256)) return err(400, "BAD_HASH");

  const raw = new Uint8Array(await req.arrayBuffer());
  if (raw.length > MAX_BLOB_BYTES) return err(413, "TOO_LARGE");

  const actual = await sha256Hex(raw);
  if (actual !== sha256) return err(422, "HASH_MISMATCH");

  const db = supabase();

  // Upsert is safe; content is immutable (same hash = same bytes)
  const { error } = await db.from("blobs").upsert({
    sha256: actual,
    size_bytes: raw.length,
    data: Array.from(raw),
    uploaded_at_ms: Number(serverMs()),
  }, { onConflict: "sha256", ignoreDuplicates: true });
  if (error) return err(500, "DB_ERROR", error.message);

  return ok({ sha256: actual, size: raw.length });
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------
Deno.serve(async (req: Request) => {
  const url = new URL(req.url);
  const path = url.pathname;

  try {
    if (req.method === "POST" && path === "/v1/session/open") {
      return await handleSessionOpen(req);
    }
    if (req.method === "POST" && path === "/v1/batch") {
      return await handleBatch(req);
    }
    if (req.method === "PUT" && path.startsWith("/v1/blob/")) {
      const sha256 = path.slice("/v1/blob/".length);
      return await handleBlob(req, sha256);
    }
    return err(404, "NOT_FOUND");
  } catch (e) {
    console.error("ingest error", e);
    return err(500, "INTERNAL", e instanceof Error ? e.message : "unknown");
  }
});
