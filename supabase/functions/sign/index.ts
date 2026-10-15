/**
 * sign/index.ts — POST /v1/schedule  and  GET /v1/export/:exam_id
 *
 * POST /v1/schedule
 *   Ingests an assessor-signed exam config (schedule) revision.
 *   Verifies the assessor signature, checks rev monotonicity, stores it.
 *   Also bootstraps an exam row if this is the first config for a new exam.
 *   The roster must already exist (use a separate admin endpoint or seed).
 *
 * GET /v1/export/:exam_id
 *   Streams a structured export bundle for offline verifier use:
 *     roster, configs, incidents, sessions (as journals), batches,
 *     acks (per-batch anchor bytes), finals, blobs.
 *   Returns a JSON manifest of all contained files and their sha256 hashes.
 *   (A real deployment would stream a zip; here we return a manifest JSON
 *    describing what a downloader should fetch per-file to conserve memory.)
 *
 * POST /v1/admin/roster
 *   Ingests the assessor-signed roster for an exam (admin / assessor only).
 *   Validates the roster, extracts server keys, and seeds the exams table.
 *
 * Ref: FORMAT_V2.md §§ 4, 5, 8.
 */

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { ed25519 } from "https://esm.sh/@noble/curves@1.4.0/ed25519";
import { hex } from "https://esm.sh/@scure/base@1.1.7";

// ---------------------------------------------------------------------------
// Shared helpers
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

function isHex64(s: unknown): s is string {
  return typeof s === "string" && /^[0-9a-f]{64}$/.test(s);
}

function isId(s: unknown): s is string {
  return typeof s === "string" && /^[A-Za-z0-9._\-]{1,64}$/.test(s);
}

function canon(obj: unknown): Uint8Array {
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

function err(status: number, code: string, detail: unknown = ""): Response {
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
// POST /v1/admin/roster — seed an exam from its assessor-signed roster
// ---------------------------------------------------------------------------
async function handleRoster(req: Request): Promise<Response> {
  const raw = new Uint8Array(await req.arrayBuffer());
  if (raw.length > 2 * 1024 * 1024) return err(413, "TOO_LARGE");

  let doc: { body: Record<string, unknown>; sig: string };
  try {
    doc = JSON.parse(new TextDecoder().decode(raw)) as typeof doc;
  } catch {
    return err(400, "BAD_JSON");
  }

  const body = doc.body;
  if (!body || !doc.sig) return err(400, "MISSING_FIELDS");

  // FORMAT_V2 §4: roster v2 body fields
  const { v, exam_id, paper_sha256, assessor } = body as Record<string, unknown>;
  if ((v !== 1 && v !== 2) || !isId(exam_id) || !isHex64(paper_sha256) || !isHex64(assessor as string)) {
    return err(400, "BAD_ROSTER_BODY");
  }

  // Verify assessor signature over body bytes (domain "roster")
  const bodyBytes = canon(body);
  if (!verifySig(assessor as string, "roster", bodyBytes, doc.sig)) {
    return err(403, "BAD_ASSESSOR_SIGNATURE");
  }

  const rosterSha256 = await sha256Hex(raw);
  const db = supabase();

  // Upsert exam (idempotent with same sha256)
  const { error: examErr } = await db.from("exams").upsert({
    exam_id,
    roster_sha256: rosterSha256,
    paper_sha256,
    roster_bytes: Array.from(raw),
    created_at_ms: Number(serverMs()),
  }, { onConflict: "exam_id", ignoreDuplicates: true });
  if (examErr) return err(500, "DB_ERROR", examErr.message);

  // Seed server keys if roster is v2
  if (v === 2 && Array.isArray(body.servers)) {
    const serverRows = (body.servers as Array<{ server_id: string; pub: string }>).map(s => ({
      exam_id,
      server_id: s.server_id,
      pub_hex: s.pub,
    }));
    if (serverRows.length > 0) {
      await db.from("servers").upsert(serverRows, {
        onConflict: "exam_id,server_id",
        ignoreDuplicates: true,
      }).throwOnError();
    }
  }

  return ok({ exam_id, roster_sha256: rosterSha256 });
}

// ---------------------------------------------------------------------------
// POST /v1/schedule — ingest an assessor-signed exam config revision
// ---------------------------------------------------------------------------
async function handleSchedule(req: Request): Promise<Response> {
  const raw = new Uint8Array(await req.arrayBuffer());
  if (raw.length > 64 * 1024) return err(413, "TOO_LARGE");

  let doc: { body: Record<string, unknown>; sig: string };
  try {
    doc = JSON.parse(new TextDecoder().decode(raw)) as typeof doc;
  } catch {
    return err(400, "BAD_JSON");
  }

  const body = doc.body;
  if (!body || !doc.sig) return err(400, "MISSING_FIELDS");

  // FORMAT_V2 §5: exam config body fields
  const required = [
    "v", "exam_id", "rev", "start_ms", "end_ms", "connect_open_ms",
    "connect_close_ms", "drain_ms", "heartbeat_ms", "outage_threshold_ms",
    "outage_cap_ms", "outage_total_ms", "save_interval_ms", "langs",
    "approved_builds", "paper_sha256",
  ];
  for (const f of required) {
    if (!(f in body)) return err(400, `MISSING_FIELD:${f}`);
  }

  const { v, exam_id, rev, start_ms, end_ms, connect_open_ms, connect_close_ms,
    drain_ms, heartbeat_ms, outage_threshold_ms, outage_cap_ms, outage_total_ms,
    save_interval_ms, paper_sha256 } = body as Record<string, unknown>;

  if (v !== 2 || !isId(exam_id) || typeof rev !== "number" || rev < 1) {
    return err(400, "BAD_CONFIG_BODY");
  }

  // Constraint checks (FORMAT_V2 §5)
  const n = (x: unknown): number => typeof x === "number" ? x : -1;
  if (n(connect_open_ms) > n(connect_close_ms)) return err(400, "CONSTRAINT_WINDOW_ORDER");
  if (n(connect_close_ms) > n(end_ms)) return err(400, "CONSTRAINT_CLOSE_AFTER_END");
  if (n(start_ms) > n(end_ms)) return err(400, "CONSTRAINT_START_AFTER_END");
  if (n(heartbeat_ms) >= n(outage_threshold_ms)) return err(400, "CONSTRAINT_HEARTBEAT");
  if (n(outage_threshold_ms) > n(outage_cap_ms)) return err(400, "CONSTRAINT_OUTAGE_CAP");
  if (n(outage_cap_ms) > n(outage_total_ms)) return err(400, "CONSTRAINT_OUTAGE_TOTAL");

  const db = supabase();

  // Fetch the exam to get the assessor pub key
  const { data: exam } = await db
    .from("exams").select("roster_bytes").eq("exam_id", exam_id).single();
  if (!exam) return err(404, "EXAM_NOT_FOUND", "upload roster first");

  const roster = JSON.parse(new TextDecoder().decode(new Uint8Array(exam.roster_bytes as number[]))) as {
    body: { assessor: string; paper_sha256: string };
    sig: string;
  };
  const assessorPub = roster.body.assessor;

  // Paper sha256 must match roster
  if (paper_sha256 !== roster.body.paper_sha256) {
    return err(400, "PAPER_SHA256_MISMATCH");
  }

  // Verify assessor signature over config body
  const bodyBytes = canon(body);
  if (!verifySig(assessorPub, "examconf", bodyBytes, doc.sig)) {
    return err(403, "BAD_ASSESSOR_SIGNATURE");
  }

  // Rev must be strictly greater than current max
  const { data: latest } = await db
    .from("exam_configs")
    .select("rev")
    .eq("exam_id", exam_id)
    .order("rev", { ascending: false })
    .limit(1)
    .single();

  if (latest && rev <= latest.rev) {
    return err(409, "STALE_REV", `current rev is ${latest.rev}; submit rev >= ${latest.rev + 1}`);
  }

  const configSha256 = await sha256Hex(raw);

  await db.from("exam_configs").insert({
    exam_id, rev,
    config_sha256: configSha256,
    config_bytes: Array.from(raw),
    start_ms, end_ms, connect_open_ms, connect_close_ms,
    drain_ms, heartbeat_ms, outage_threshold_ms,
    outage_cap_ms, outage_total_ms, save_interval_ms,
    ingested_at_ms: Number(serverMs()),
  }).throwOnError();

  return ok({ exam_id, rev, config_sha256: configSha256 });
}

// ---------------------------------------------------------------------------
// GET /v1/export/:exam_id — examiner bundle manifest
// ---------------------------------------------------------------------------
async function handleExport(examId: string): Promise<Response> {
  const db = supabase();

  // Verify exam exists
  const { data: exam } = await db
    .from("exams").select("exam_id, roster_sha256").eq("exam_id", examId).single();
  if (!exam) return err(404, "EXAM_NOT_FOUND");

  // Collect manifest entries for each artifact type
  const manifest: Array<{ path: string; sha256: string; bytes?: number }> = [];

  // Roster
  const { data: examRow } = await db
    .from("exams").select("roster_sha256, roster_bytes").eq("exam_id", examId).single();
  if (examRow) {
    const bytes = new Uint8Array(examRow.roster_bytes as number[]);
    manifest.push({ path: `roster/${examRow.roster_sha256}.json`, sha256: examRow.roster_sha256, bytes: bytes.length });
  }

  // Configs
  const { data: configs } = await db
    .from("exam_configs").select("rev, config_sha256, config_bytes").eq("exam_id", examId);
  for (const c of configs ?? []) {
    manifest.push({ path: `configs/rev${c.rev}_${c.config_sha256}.json`, sha256: c.config_sha256 });
  }

  // Incidents
  const { data: incidents } = await db
    .from("incidents").select("incident_sha256").eq("exam_id", examId);
  for (const i of incidents ?? []) {
    manifest.push({ path: `incidents/${i.incident_sha256}.json`, sha256: i.incident_sha256 });
  }

  // Sessions: batches, acks, finals
  const { data: sessions } = await db
    .from("sessions").select("session_id, ws_id, final_receipt_bytes, manifest_sha256")
    .eq("exam_id", examId);

  for (const s of sessions ?? []) {
    const { data: batches } = await db
      .from("batches")
      .select("first_seq, batch_sha256, ack_bytes")
      .eq("exam_id", examId)
      .eq("session_id", s.session_id)
      .eq("ws_id", s.ws_id)
      .order("first_seq", { ascending: true });

    for (const b of batches ?? []) {
      manifest.push({
        path: `batches/${s.session_id}/${s.ws_id}/${b.first_seq}_${b.batch_sha256}.bin`,
        sha256: b.batch_sha256,
      });
      if (b.ack_bytes) {
        const ackSha256 = await sha256Hex(new Uint8Array(b.ack_bytes as number[]));
        manifest.push({
          path: `acks/${s.session_id}/${s.ws_id}/${b.first_seq}_${ackSha256}.bin`,
          sha256: ackSha256,
        });
      }
    }

    if (s.final_receipt_bytes) {
      const recSha256 = await sha256Hex(new Uint8Array(s.final_receipt_bytes as number[]));
      manifest.push({
        path: `finals/${s.session_id}/${s.ws_id}.imr2`,
        sha256: recSha256,
      });
    }

    // Blobs
    const { data: sblobs } = await db
      .from("session_blobs").select("sha256")
      .eq("exam_id", examId)
      .eq("session_id", s.session_id)
      .eq("ws_id", s.ws_id);
    for (const bl of sblobs ?? []) {
      manifest.push({
        path: `blobs/${bl.sha256.slice(0, 2)}/${bl.sha256}`,
        sha256: bl.sha256,
      });
    }
  }

  return ok({
    exam_id: examId,
    exported_at_ms: Number(serverMs()),
    files: manifest,
    note: "Download each file from GET /v1/export/:exam_id/file?path=<path>",
  });
}

// ---------------------------------------------------------------------------
// POST /v1/admin/incident — ingest an assessor-signed incident document
// ---------------------------------------------------------------------------
async function handleIncident(req: Request): Promise<Response> {
  const raw = new Uint8Array(await req.arrayBuffer());
  if (raw.length > 16 * 1024) return err(413, "TOO_LARGE");

  let doc: { body: Record<string, unknown>; sig: string };
  try {
    doc = JSON.parse(new TextDecoder().decode(raw)) as typeof doc;
  } catch {
    return err(400, "BAD_JSON");
  }

  const body = doc.body;
  const { v, exam_id, from_ms, to_ms } = body as Record<string, unknown>;
  if (v !== 1 || !isId(exam_id) || typeof from_ms !== "number" || typeof to_ms !== "number" || to_ms <= from_ms) {
    return err(400, "BAD_INCIDENT_BODY");
  }

  const db = supabase();
  const { data: exam } = await db
    .from("exams").select("roster_bytes").eq("exam_id", exam_id).single();
  if (!exam) return err(404, "EXAM_NOT_FOUND");

  const roster = JSON.parse(new TextDecoder().decode(new Uint8Array(exam.roster_bytes as number[]))) as {
    body: { assessor: string };
  };
  const assessorPub = roster.body.assessor;
  const bodyBytes = canon(body);
  if (!verifySig(assessorPub, "incident", bodyBytes, doc.sig)) {
    return err(403, "BAD_ASSESSOR_SIGNATURE");
  }

  const incidentSha256 = await sha256Hex(raw);
  await db.from("incidents").upsert({
    exam_id, incident_sha256: incidentSha256,
    from_ms, to_ms,
    incident_bytes: Array.from(raw),
    ingested_at_ms: Number(serverMs()),
  }, { onConflict: "incident_sha256", ignoreDuplicates: true }).throwOnError();

  return ok({ exam_id, incident_sha256: incidentSha256 });
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------
Deno.serve(async (req: Request) => {
  const url = new URL(req.url);
  const path = url.pathname;

  try {
    if (req.method === "POST" && path === "/v1/schedule") {
      return await handleSchedule(req);
    }
    if (req.method === "POST" && path === "/v1/admin/roster") {
      return await handleRoster(req);
    }
    if (req.method === "POST" && path === "/v1/admin/incident") {
      return await handleIncident(req);
    }
    if (req.method === "GET" && path.startsWith("/v1/export/")) {
      const examId = path.slice("/v1/export/".length).split("/")[0];
      return await handleExport(examId);
    }
    return new Response(JSON.stringify({ error: "NOT_FOUND" }), {
      status: 404,
      headers: { "Content-Type": "application/json" },
    });
  } catch (e) {
    console.error("sign error", e);
    return new Response(JSON.stringify({ error: "INTERNAL" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
});
