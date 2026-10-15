// supabase/functions/board/index.ts
//
// Read-only edge function serving the teacher board from the Supabase database.
// Requires Authorization: Bearer <TEACHER_TOKEN> matching the env var.

import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const EXPECTED_TOKEN = Deno.env.get("TEACHER_TOKEN") || "";

function err(status: number, message: string) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
  });
}

function ok(data: unknown) {
  return new Response(JSON.stringify(data), {
    status: 200,
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
  });
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, {
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Authorization, Content-Type",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
      },
    });
  }

  if (!EXPECTED_TOKEN || EXPECTED_TOKEN.length < 16) {
    return err(503, "teacher board not configured (TEACHER_TOKEN not set or too short)");
  }
  const auth = req.headers.get("Authorization") || "";
  const match = auth.match(/^Bearer\s+(.+)$/i);
  if (!match || match[1] !== EXPECTED_TOKEN) {
    return err(401, "unauthorized");
  }

  const url = new URL(req.url);
  const examId = url.searchParams.get("exam_id");
  if (!examId) return err(400, "exam_id query parameter required");

  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  );

  // Load active config for exam_end_ms and exam state
  const { data: cfg } = await supabase
    .from("active_configs")
    .select("end_ms, drain_ms, rev")
    .eq("exam_id", examId)
    .single();

  const nowMs = Date.now();

  // Load roster seats
  const { data: exam } = await supabase
    .from("exams")
    .select("roster_bytes")
    .eq("exam_id", examId)
    .single();

  let rosterSeats: string[] = [];
  if (exam?.roster_bytes) {
    try {
      const parsed = JSON.parse(new TextDecoder().decode(new Uint8Array(exam.roster_bytes)));
      const seats = parsed.body?.seats || [];
      rosterSeats = seats.map((s: { ws_id: string }) => s.ws_id);
    } catch (_e) {
      /* ignore */
    }
  }

  // Handle single-seat detail: /board?exam_id=...&seat=STN-19
  const seatId = url.searchParams.get("seat");
  if (seatId) {
    const { data: batches } = await supabase
      .from("batches")
      .select("first_seq, last_seq, head, ingested_at_ms")
      .eq("exam_id", examId)
      .eq("ws_id", seatId)
      .order("first_seq", { ascending: false })
      .limit(10);
    return ok({ seat_id: seatId, batches: batches || [] });
  }

  // Load all sessions for this exam
  const { data: sessions } = await supabase
    .from("sessions")
    .select("ws_id, t_last_contact_ms, held_upto, last_boot_id, last_typ, last_file, last_event_id, last_seq, last_admit_ms")
    .eq("exam_id", examId);

  const seen = new Set<string>();
  const seatsOut: Array<Record<string, unknown>> = [];

  for (const s of sessions || []) {
    seen.add(s.ws_id);
    const ageS = s.t_last_contact_ms ? Math.max(0, Math.floor((nowMs - s.t_last_contact_ms) / 1000)) : 99999;
    const unsent = (s.last_seq !== null && s.held_upto !== null)
      ? Math.max(0, Number(s.last_seq) - Number(s.held_upto))
      : 0;
    seatsOut.push({
      seat_id: s.ws_id,
      state: ageS <= 20 ? "active" : ageS <= 60 ? "quiet" : "offline",
      age_s: ageS,
      boot_count: 1,
      unsent,
      last_action: s.last_typ ? (s.last_file ? `${s.last_typ} ${s.last_file}` : s.last_typ) : null,
      last_admit_ms: s.last_admit_ms,
    });
  }

  // Roster seats not yet seen
  for (const r of rosterSeats) {
    if (!seen.has(r)) {
      seatsOut.push({
        seat_id: r,
        state: "not_started",
        age_s: null,
        boot_count: 0,
        unsent: 0,
        last_action: null,
      });
    }
  }

  seatsOut.sort((a, b) => String(a.seat_id).localeCompare(String(b.seat_id)));

  const activeCount = seatsOut.filter(s => s.state === "active").length;
  const offlineCount = seatsOut.filter(s => s.state === "offline").length;

  return ok({
    ts_ms: nowMs,
    exam_end_ms: cfg?.end_ms ?? null,
    total_seats: seatsOut.length,
    active_count: activeCount,
    offline_count: offlineCount,
    room_alert: offlineCount >= 3 && offlineCount >= seatsOut.length * 0.4,
    seats: seatsOut,
  });
});
