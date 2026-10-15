-- =============================================================================
-- Immutable v2 – Supabase schema, RLS, triggers
-- Migration: 00001_immutable_schema.sql
-- =============================================================================
-- All timestamps are stored as BIGINT milliseconds (Unix epoch, server clock).
-- The server is the authority on time; client timestamps are stored but never
-- trusted for window enforcement.
-- =============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- Extensions
-- ---------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS pgcrypto;    -- gen_random_uuid(), sha256 via digest()

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

-- is_hex(text, n) – pure SQL guard used in CHECK constraints
CREATE OR REPLACE FUNCTION is_hex(s text, n integer)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT AS $$
  SELECT length(s) = n AND s ~ '^[0-9a-f]+$';
$$;

-- is_id(text) – matches [A-Za-z0-9._-]{1,64}
CREATE OR REPLACE FUNCTION is_id(s text)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT AS $$
  SELECT s ~ '^[A-Za-z0-9._\-]{1,64}$';
$$;

-- server_ms() – current time in Unix milliseconds, used in DEFAULT expressions
CREATE OR REPLACE FUNCTION server_ms()
RETURNS bigint LANGUAGE sql STABLE AS $$
  SELECT (extract(epoch FROM clock_timestamp()) * 1000)::bigint;
$$;

-- ---------------------------------------------------------------------------
-- 1. exams
-- One row per exam. Created by the assessor at setup time.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exams (
  exam_id          text        PRIMARY KEY CHECK (is_id(exam_id)),
  roster_sha256    text        NOT NULL CHECK (is_hex(roster_sha256, 64)),
  paper_sha256     text        NOT NULL CHECK (is_hex(paper_sha256, 64)),
  roster_bytes     bytea       NOT NULL,        -- canonical roster file
  created_at_ms    bigint      NOT NULL DEFAULT server_ms()
);

-- ---------------------------------------------------------------------------
-- 2. exam_configs (schedules)
-- Assessor-signed config revisions.  rev increases monotonically.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exam_configs (
  exam_id             text    NOT NULL REFERENCES exams(exam_id),
  rev                 integer NOT NULL CHECK (rev >= 1),
  config_sha256       text    NOT NULL CHECK (is_hex(config_sha256, 64)),
  config_bytes        bytea   NOT NULL,   -- raw canonical signed file
  start_ms            bigint  NOT NULL,
  end_ms              bigint  NOT NULL CHECK (end_ms >= start_ms),
  connect_open_ms     bigint  NOT NULL,
  connect_close_ms    bigint  NOT NULL CHECK (connect_close_ms >= connect_open_ms
                                          AND connect_close_ms <= end_ms),
  drain_ms            bigint  NOT NULL CHECK (drain_ms >= 0),
  heartbeat_ms        bigint  NOT NULL CHECK (heartbeat_ms > 0),
  outage_threshold_ms bigint  NOT NULL,
  outage_cap_ms       bigint  NOT NULL CHECK (outage_cap_ms >= outage_threshold_ms),
  outage_total_ms     bigint  NOT NULL CHECK (outage_total_ms >= outage_cap_ms),
  save_interval_ms    bigint  NOT NULL CHECK (save_interval_ms > 0),
  ingested_at_ms      bigint  NOT NULL DEFAULT server_ms(),
  PRIMARY KEY (exam_id, rev)
);

-- Active config: the highest rev for an exam
CREATE OR REPLACE VIEW active_configs AS
  SELECT DISTINCT ON (exam_id) *
  FROM exam_configs
  ORDER BY exam_id, rev DESC;

-- ---------------------------------------------------------------------------
-- 3. servers
-- Roster-enrolled server keys. Populated from roster v2 `servers` list.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS servers (
  exam_id    text NOT NULL REFERENCES exams(exam_id),
  server_id  text NOT NULL CHECK (is_id(server_id)),
  pub_hex    text NOT NULL CHECK (is_hex(pub_hex, 64)),
  PRIMARY KEY (exam_id, server_id)
);

-- ---------------------------------------------------------------------------
-- 4. sessions
-- One row per (exam, seat).  State machine: open → finalized.
-- ---------------------------------------------------------------------------
CREATE TYPE session_finalize_reason AS ENUM (
  'submitted', 'window_end', 'grace_expired'
);

CREATE TABLE IF NOT EXISTS sessions (
  exam_id           text    NOT NULL REFERENCES exams(exam_id),
  session_id        text    NOT NULL CHECK (is_id(session_id)),
  ws_id             text    NOT NULL CHECK (is_id(ws_id)),
  candidate         text    CHECK (candidate IS NULL OR is_id(candidate)),
  seat_pub          text    NOT NULL CHECK (is_hex(seat_pub, 64)),
  opened_at_ms      bigint  NOT NULL,           -- server_ms() at session/open
  schedule_sha256   text    NOT NULL CHECK (is_hex(schedule_sha256, 64)),
  schedule_rev      integer NOT NULL,
  -- mutable state
  held_upto         integer NOT NULL DEFAULT -1, -- highest acked seq (-1 = none)
  held_head         text    NOT NULL DEFAULT repeat('0', 64)
                            CHECK (is_hex(held_head, 64)),
  t_last_contact_ms bigint  NOT NULL,            -- server_ms of last accepted contact
  outage_used_ms    bigint  NOT NULL DEFAULT 0,  -- sum of counted_ms over closed outages
  -- finalization (NULL while open)
  finalized_at_ms   bigint,
  finalize_reason   session_finalize_reason,
  final_seq         integer,
  final_head        text    CHECK (final_head IS NULL OR is_hex(final_head, 64)),
  manifest_sha256   text    CHECK (manifest_sha256 IS NULL OR is_hex(manifest_sha256, 64)),
  file_count        integer,
  submit_seq        integer,
  journal_head      text    CHECK (journal_head IS NULL OR is_hex(journal_head, 64)),
  last_confirmed_ms bigint,
  outage_count      integer NOT NULL DEFAULT 0,
  final_receipt_bytes bytea,                    -- cached FINAL document bytes
  PRIMARY KEY (exam_id, session_id, ws_id),
  FOREIGN KEY (exam_id, schedule_rev) REFERENCES exam_configs(exam_id, rev)
);

-- Convenience: fast lookup by ws
CREATE INDEX IF NOT EXISTS sessions_ws_idx ON sessions(exam_id, ws_id);

-- ---------------------------------------------------------------------------
-- 5. batches
-- Raw signed batch files as uploaded by the workstation.
-- Each batch covers a contiguous range of events for one seat.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS batches (
  exam_id      text    NOT NULL,
  session_id   text    NOT NULL,
  ws_id        text    NOT NULL,
  first_seq    integer NOT NULL CHECK (first_seq >= 0),
  last_seq     integer NOT NULL CHECK (last_seq >= first_seq),
  head         text    NOT NULL CHECK (is_hex(head, 64)),
  batch_sha256 text    NOT NULL CHECK (is_hex(batch_sha256, 64)),
  batch_bytes  bytea   NOT NULL,
  ack_bytes    bytea,            -- witness-style anchor signed by the server key; NULL until acked
  ingested_at_ms bigint NOT NULL DEFAULT server_ms(),
  PRIMARY KEY (exam_id, session_id, ws_id, first_seq),
  FOREIGN KEY (exam_id, session_id, ws_id) REFERENCES sessions(exam_id, session_id, ws_id)
);

CREATE INDEX IF NOT EXISTS batches_last_seq_idx
  ON batches(exam_id, session_id, ws_id, last_seq);

-- ---------------------------------------------------------------------------
-- 6. pings
-- Heartbeats from workstations.  Only the latest per (exam,session,ws) is
-- meaningful for liveness; the table is an audit trail.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS pings (
  exam_id    text    NOT NULL,
  session_id text    NOT NULL,
  ws_id      text    NOT NULL,
  boot_id    text    NOT NULL CHECK (is_id(boot_id)),
  boot_ns    bigint  NOT NULL CHECK (boot_ns >= 0),
  last_seq   integer NOT NULL CHECK (last_seq >= 0),
  server_ms  bigint  NOT NULL DEFAULT server_ms(),
  PRIMARY KEY (exam_id, session_id, ws_id, server_ms),
  FOREIGN KEY (exam_id, session_id, ws_id) REFERENCES sessions(exam_id, session_id, ws_id)
);

-- Latest ping per session
CREATE INDEX IF NOT EXISTS pings_latest_idx
  ON pings(exam_id, session_id, ws_id, server_ms DESC);

-- ---------------------------------------------------------------------------
-- 7. blobs
-- File content store. Referenced by manifest entries.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS blobs (
  sha256      text    PRIMARY KEY CHECK (is_hex(sha256, 64)),
  size_bytes  bigint  NOT NULL CHECK (size_bytes >= 0),
  data        bytea   NOT NULL,
  uploaded_at_ms bigint NOT NULL DEFAULT server_ms()
);

-- Per-session blob quota tracking
CREATE TABLE IF NOT EXISTS session_blobs (
  exam_id    text    NOT NULL,
  session_id text    NOT NULL,
  ws_id      text    NOT NULL,
  sha256     text    NOT NULL REFERENCES blobs(sha256),
  PRIMARY KEY (exam_id, session_id, ws_id, sha256),
  FOREIGN KEY (exam_id, session_id, ws_id) REFERENCES sessions(exam_id, session_id, ws_id)
);

-- ---------------------------------------------------------------------------
-- 8. journal
-- Server-authored append-only chain of events (section 7 of FORMAT_V2).
-- Each entry is signed by the server key; chain commits to ordering.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS journal (
  exam_id      text    NOT NULL,
  session_id   text    NOT NULL,
  ws_id        text    NOT NULL,
  seq          integer NOT NULL CHECK (seq >= 0),
  kind         text    NOT NULL,   -- CONTACT_GAP, SESSION_OPEN, SESSION_CLOSE, WINDOW_CLOSE, etc.
  body_json    jsonb   NOT NULL,
  prev_hash    text    NOT NULL CHECK (is_hex(prev_hash, 64)),
  entry_hash   text    NOT NULL CHECK (is_hex(entry_hash, 64)),
  server_ms    bigint  NOT NULL DEFAULT server_ms(),
  PRIMARY KEY (exam_id, session_id, ws_id, seq),
  FOREIGN KEY (exam_id, session_id, ws_id) REFERENCES sessions(exam_id, session_id, ws_id)
);

-- ---------------------------------------------------------------------------
-- 9. incidents
-- Assessor-signed lab-wide fault windows. Subtracted from every session's
-- outage accounting.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
  exam_id       text    NOT NULL REFERENCES exams(exam_id),
  incident_sha256 text  PRIMARY KEY CHECK (is_hex(incident_sha256, 64)),
  from_ms       bigint  NOT NULL,
  to_ms         bigint  NOT NULL CHECK (to_ms > from_ms),
  incident_bytes bytea  NOT NULL,
  ingested_at_ms bigint NOT NULL DEFAULT server_ms()
);

-- ---------------------------------------------------------------------------
-- 10. late_tail
-- Data arriving after a session is finalized – excluded from the submission,
-- kept for dispute resolution.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS late_tail (
  exam_id      text    NOT NULL,
  session_id   text    NOT NULL,
  ws_id        text    NOT NULL,
  kind         text    NOT NULL,   -- 'batch' | 'ping' | 'blob'
  sha256       text    NOT NULL CHECK (is_hex(sha256, 64)),
  data         bytea   NOT NULL,
  arrived_at_ms bigint NOT NULL DEFAULT server_ms(),
  PRIMARY KEY (exam_id, session_id, ws_id, kind, sha256)
);

-- ---------------------------------------------------------------------------
-- 11. Triggers
-- ---------------------------------------------------------------------------

-- 11a. Update sessions.t_last_contact_ms on batch insert
CREATE OR REPLACE FUNCTION trg_update_contact_on_batch()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  UPDATE sessions
  SET t_last_contact_ms = NEW.ingested_at_ms
  WHERE exam_id   = NEW.exam_id
    AND session_id = NEW.session_id
    AND ws_id      = NEW.ws_id
    AND t_last_contact_ms < NEW.ingested_at_ms;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE TRIGGER trg_batch_contact
AFTER INSERT ON batches
FOR EACH ROW EXECUTE FUNCTION trg_update_contact_on_batch();

-- 11b. Update sessions.t_last_contact_ms on ping insert
CREATE OR REPLACE FUNCTION trg_update_contact_on_ping()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  UPDATE sessions
  SET t_last_contact_ms = NEW.server_ms
  WHERE exam_id    = NEW.exam_id
    AND session_id = NEW.session_id
    AND ws_id      = NEW.ws_id
    AND t_last_contact_ms < NEW.server_ms;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE TRIGGER trg_ping_contact
AFTER INSERT ON pings
FOR EACH ROW EXECUTE FUNCTION trg_update_contact_on_ping();

-- 11c. Prevent mutation of finalized sessions (except storing the final receipt)
CREATE OR REPLACE FUNCTION trg_guard_finalized_session()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  -- Allow the finalization write itself (setting finalized_at_ms)
  IF OLD.finalized_at_ms IS NULL THEN
    RETURN NEW;
  END IF;
  -- After finalization only final_receipt_bytes may be written
  IF NEW.final_receipt_bytes IS DISTINCT FROM OLD.final_receipt_bytes
     AND NEW.held_upto = OLD.held_upto
     AND NEW.held_head = OLD.held_head
     AND NEW.t_last_contact_ms = OLD.t_last_contact_ms
  THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'session is finalized; no further state changes allowed'
    USING ERRCODE = 'P0001';
END;
$$;

CREATE OR REPLACE TRIGGER trg_session_immutable
BEFORE UPDATE ON sessions
FOR EACH ROW EXECUTE FUNCTION trg_guard_finalized_session();

-- 11d. Reject batches for finalized sessions (routed to late_tail by the Edge Function;
--      this is a belt-and-suspenders guard at the DB layer)
CREATE OR REPLACE FUNCTION trg_guard_batch_finalized()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  v_fin bigint;
BEGIN
  SELECT finalized_at_ms INTO v_fin
  FROM sessions
  WHERE exam_id    = NEW.exam_id
    AND session_id = NEW.session_id
    AND ws_id      = NEW.ws_id;
  IF v_fin IS NOT NULL THEN
    RAISE EXCEPTION 'session is finalized; batch rejected'
      USING ERRCODE = 'P0002';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE TRIGGER trg_batch_not_finalized
BEFORE INSERT ON batches
FOR EACH ROW EXECUTE FUNCTION trg_guard_batch_finalized();

-- ---------------------------------------------------------------------------
-- 12. Row-Level Security
-- ---------------------------------------------------------------------------
-- Strategy:
--   * Workstation calls use the `service_role` key (server-to-server, within Edge Functions).
--     Edge Functions validate signatures before touching the DB; the DB layer trusts them.
--   * The public anon role is DENIED everything by default.
--   * A special `examiner` role (created below) may read but not write.
--   * `service_role` is the Supabase built-in superuser used by Edge Functions.
-- ---------------------------------------------------------------------------

ALTER TABLE exams          ENABLE ROW LEVEL SECURITY;
ALTER TABLE exam_configs   ENABLE ROW LEVEL SECURITY;
ALTER TABLE servers        ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions       ENABLE ROW LEVEL SECURITY;
ALTER TABLE batches        ENABLE ROW LEVEL SECURITY;
ALTER TABLE pings          ENABLE ROW LEVEL SECURITY;
ALTER TABLE blobs          ENABLE ROW LEVEL SECURITY;
ALTER TABLE session_blobs  ENABLE ROW LEVEL SECURITY;
ALTER TABLE journal        ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents      ENABLE ROW LEVEL SECURITY;
ALTER TABLE late_tail      ENABLE ROW LEVEL SECURITY;

-- service_role bypasses RLS by default in Supabase; these policies are for
-- any custom roles and the anon role.

-- Deny anon everything (default-deny is already the RLS default when enabled,
-- but be explicit so a future change cannot silently open access).
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'examiner') THEN
    CREATE ROLE examiner NOLOGIN;
  END IF;
END $$;

-- Examiner: read-only on evidence tables, cannot see seat keys or private bytes.
-- Note: prod deployments should use a proper JWT claim check. These policies use
-- current_user for simplicity; replace with auth.role() in Supabase Auth context.

CREATE POLICY examiner_read_exams         ON exams         FOR SELECT TO examiner USING (true);
CREATE POLICY examiner_read_exam_configs  ON exam_configs   FOR SELECT TO examiner USING (true);
CREATE POLICY examiner_read_servers       ON servers        FOR SELECT TO examiner USING (true);
CREATE POLICY examiner_read_sessions      ON sessions       FOR SELECT TO examiner USING (true);
CREATE POLICY examiner_read_batches       ON batches        FOR SELECT TO examiner USING (true);
CREATE POLICY examiner_read_pings         ON pings          FOR SELECT TO examiner USING (true);
-- blobs: examiners may read content for verification
CREATE POLICY examiner_read_blobs         ON blobs          FOR SELECT TO examiner USING (true);
CREATE POLICY examiner_read_session_blobs ON session_blobs  FOR SELECT TO examiner USING (true);
CREATE POLICY examiner_read_journal       ON journal        FOR SELECT TO examiner USING (true);
CREATE POLICY examiner_read_incidents     ON incidents      FOR SELECT TO examiner USING (true);
CREATE POLICY examiner_read_late_tail     ON late_tail      FOR SELECT TO examiner USING (true);

-- Deny anon write to everything (SELECT also denied – default with RLS enabled and no policy)
-- No explicit anon policies → all anon access denied.

COMMIT;
