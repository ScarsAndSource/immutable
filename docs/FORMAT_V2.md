# Immutable byte format, v2 (server-anchored mode)

v2 is a delta on `FORMAT.md` (v1). Everything in v1 stays normative unless a section
below overrides it. If code and this file disagree, the code is wrong.

Overrides at a glance:
- Event body `v` is 2. Prefix `immutable/v1/` is KEPT: it names the domain family, not the
  format version. Domains added: `examconf`, `incident`, `journal`, `final`.
- Roster `v` 2 adds `servers`. Verifiers accept roster v1 (no servers) and v2.
- Event schemas change (section 6). Path rules get stricter (section 6.3).
- The receipt becomes a server-signed FINAL record, `IMR2.` (section 11). The v1 `IMR1.`
  workstation receipt is kept only for offline-fallback mode (section 16).

## 0. Principles
1. We prove what was recorded and when. We do not prove the student worked alone.
2. The server owns time. Client clocks are claims, bounded by server acks.
3. Every state the server decides (window, outage, expiry, finalization) is a pure
   function of signed inputs and server timestamps, so any evaluator gets the same answer.
4. The verifier runs offline on an exported bundle. The server is transport and anchor,
   never the judge.

## 1. Roles
| Role | Holds | Does |
|---|---|---|
| Assessor | assessor key (offline) | signs roster, exam config, incidents, transfers |
| Server (Edge Functions + Postgres) | server key (Edge Function secret) | validates, orders, acks, journals, finalizes, signs FINAL |
| Workstation (shell + agent) | seat key | WAL, chain, signed batches, uploads |
| Student | receipt file | verifies receipt offline |
| Verifier | pinned assessor key | judges an exported bundle offline |

Authorization to open a session is possession of the seat key enrolled in the roster
(proof of possession, domain `enroll` flow of v1 section 9) plus the seat being inside the
connect window. Seat assignment to a human is the invigilator's job. No passwords.

## 2. Canonical JSON delta
v1 section 1 is unchanged, with one addition:

**ASCII-key rule.** Every object key in a v2 server-facing document (exam config, incident,
journal body, anchor, final receipt, batch header, event body) is ASCII `[a-z0-9_]`.
Under that rule `canon.dumps` output is byte-identical to RFC 8785 (JCS) for the value
subset we allow (no floats; integers within 2^53-1). Key order by code point and by UTF-16
unit only differ for astral keys, which the rule forbids.
Values may be any NFC Unicode. A decoder MUST reject non-ASCII keys in those documents.
Vectors: `vectors/v2.json` cases C1 to C4.

## 3. Domains added
`examconf`, `incident`, `journal`, `final`. Same construction as v1 section 2:
`"immutable/v1/" || domain || 0x00 || data`. Server acks reuse `cosign`.

## 4. Roster v2
Body adds `servers: [{server_id, pub}]`, sorted by server_id, no duplicates. The server key
must be distinct from the assessor, every seat and every witness key. The roster is still
signed by the assessor and pinned by every verifier.

## 5. Exam config
File: canonical `{"body": B, "sig": hex}`, sig by the assessor key, domain `examconf`.

B fields (all required):
`v` (2), `exam_id`, `rev` (uint, starts at 1), `start_ms`, `end_ms`, `connect_open_ms`,
`connect_close_ms`, `drain_ms`, `heartbeat_ms`, `outage_threshold_ms`, `outage_cap_ms`,
`outage_total_ms`, `save_interval_ms`, `langs` (sorted list of language ids),
`approved_builds` (sorted list of sha256, may be empty), `paper_sha256`.
All times are server-clock Unix ms, UTC.

Constraints: `connect_open_ms <= connect_close_ms <= end_ms`, `start_ms <= end_ms`,
`heartbeat_ms < outage_threshold_ms <= outage_cap_ms <= outage_total_ms`.

Immutability: once any session has opened, no field may change except by publishing
`rev+1` signed by the assessor. Every revision is journaled. A final receipt names the
`schedule_sha256` (sha256_hex of the config FILE bytes) in force at finalization. The
examiner can set date, start, end and connection window only by signing a config.

Defaults (my guesses, not measured):
`heartbeat_ms` 5000, `outage_threshold_ms` 15000, `outage_cap_ms` 120000,
`outage_total_ms` 300000, `save_interval_ms` 2000, `drain_ms` 30000.

## 6. Events v2
Event body is v1 section 3 with `v` = 2.

### 6.1 Schemas (replaces v1 `SCHEMAS` for v=2; unlisted types unchanged)
| Type | Fields | Status |
|---|---|---|
| SESSION_START | paper_sha256, roster_sha256, schedule_sha256, agent_ver, agent_sha256, platform (windows/linux/macos) | changed |
| RUN_START | path, sha256, lang, toolchain | changed |
| BUILD_END | path, exit_code, stderr_sha256, duration_ms | new |
| RUN_END | exit_code, stdout_sha256, duration_ms | unchanged |
| CLIPBOARD_BLOCKED | action (copy/cut/paste), length (uint, code points, 0 if not text) | new |
| FOCUS_LOST | reason (blur/hidden/minimized) | new |
| FOCUS_GAINED | away_ms (uint) | new |
| SYNC_STATE | state (synced/probing/locked/resynced), last_confirmed_seq (uint) | new |
| others | as v1 | unchanged |

`lang` is one of `python, c, cpp, java, js` and must appear in the exam config `langs`.
`toolchain` is a short printable ASCII id such as `gcc-13.2`. `agent_sha256` is the hash of
the packaged shell plus sidecar build. A value outside `approved_builds` is a FLAG, not a
finding: a user with admin rights can report any value, so it is a self-report.

No content ever: clipboard content, window titles, process names, URLs, keystrokes,
screens. Length and time only. The allow-list is still the structural guarantee, and
`docs/POLICY.md` is regenerated from it.

SYNC_STATE events are client claims written to the WAL. The server journal (section 7) is
the authority on what the server saw.

### 6.2 Artifact hashing (language independent)
- File hash: plain SHA-256 of raw bytes, lowercase hex. No newline conversion, no BOM
  handling, no encoding step, ever. The editor must save exactly what the student typed,
  with the line-ending style of that file preserved.
- Manifest: canonical `{v, exam_id, session_id, ws_id, files:[{path,sha256,size}]}` with
  `files` sorted by `path` in code point order. Manifest hash is plain SHA-256 of the
  manifest bytes. Keys are ASCII so JS, Go, Java and Python agree.
- A hasher in any language passes iff it reproduces `vectors/v2.json` cases F1 to F3 and M1.

### 6.3 Paths (stricter than v1, on every platform)
In addition to v1 `_relpath` (NFC, relative, no `..`, no `\`, no NUL, at most 256 chars),
a v2 path MUST NOT contain, in any component:
- characters `< > : " | ? *` or any control character (this blocks Windows alternate data
  streams such as `a.txt:x`)
- a trailing dot or space
- a reserved device name, case-insensitively, with or without extension:
  `CON PRN AUX NUL COM1-COM9 LPT1-LPT9`
- a component longer than 100 characters
And within one manifest no two paths may be equal after Unicode case folding.
Violations are skipped and listed under `skipped` (v1 T15), never silently dropped.

## 7. Server journal
Per session, hash-chained, server-written. Entry body (all required):
`v` (2), `exam_id`, `session_id`, `jseq` (from 0), `prev` (64 zeros at genesis), `type`,
`server_ms`, `data`. Hash = `H(journal, canonical(body))`.

Types and data:
| Type | data |
|---|---|
| SESSION_OPENED | ws_id, rev, resumed (bool), held_upto (uint) |
| SESSION_REJECTED | reason (not_enrolled/outside_connect_window/already_active/finalized/rollback) |
| CONTACT_GAP | from_ms, to_ms, gross_ms, subtracted_ms, counted_ms |
| FORK_REJECTED | seq, held_head |
| STALE_REJECTED | first_seq, held_upto |
| SCHEDULE_REV | rev, sha256 |
| INCIDENT_APPLIED | sha256 |
| GRACE_EXPIRED | effective_ms, last_contact_ms |
| FINALIZED | reason, final_seq, head, effective_ms |

A journal row is never updated or deleted. The FINAL receipt carries the journal head at
finalization. Entries after that (late data rejections) extend the chain.

Server ticks: a scheduler writes a global `tick(server_ms)` only after a successful
self-call to the ingest function. A hole longer than `2 * heartbeat_ms` is "server dark".

## 8. Server protocol
Same philosophy as v1 section 12: 4xx permanent (stop retrying), network error and 5xx
retried with backoff.

| Call | Purpose | Success |
|---|---|---|
| POST /v1/session/open | seat-key-signed open request | 200 `{server_ms, deadline_ms, held_upto, held_head, rev}` |
| POST /v1/batch | signed batch file | 200 witness-kind anchor file signed by the server key |
| POST /v1/ping | signed ping (v1 section 12 format) | 200 `{server_ms, remaining_ms, held_upto}` |
| PUT /v1/blob/{sha256} | file bytes, size at most 2 MiB | 200; server re-hashes, mismatch is 422 |
| POST /v1/finalize | after SESSION_END is acked | 200 FINAL receipt, or 409 `MISSING_BLOBS {list}` |
| GET /v1/receipt/{session} | student or examiner | 200 identical bytes, or 404 not finalized |
| GET /v1/export/{exam} | examiner bundle | roster, configs, incidents, events, batches, acks, journals, finals, blobs |
| POST /v1/schedule | assessor-signed config | 200 |

Error bodies: `{error, detail}` plus, for conflicts, `{held_upto, held_head}`.
Codes: 409 FORK (same seq, different hash; recorded, never overwritten), 409 STALE (seq at
or below held with the same hash is a 200 no-op; below held with a different chain is a
FORK), 409 ROLLBACK (client chain shorter than held), 403 OUTSIDE_WINDOW,
410 FINALIZED, 413 TOO_LARGE, 429 RATE.

Ack = v1 anchor file kind `witness`, holder = `server_id`, `seen_ms` = the FIRST server
time this event was held, signed under `cosign`. Re-sending an acked batch returns a
byte-identical anchor. The workstation stores every ack. That is what lets a student prove
what the server once held even if the database is later edited.

Server rules on every call: signature verified over raw bytes before parsing; size and depth
limits of v1; exam, session, seat and seq inside signed bytes; event types checked against
the allow-list; batch at most 256 events; at most 60 batches per session per minute;
at most 50 MiB blobs per session (all are guesses to be measured).

Window rules: `session/open` requires `connect_open_ms <= T <= connect_close_ms`
(T = database `now()`, never a client value). Batches require
`T <= end_ms + drain_ms`, session not finalized, and contiguous seq.

## 9. Client sync state machine
| State | Editor | Meaning |
|---|---|---|
| CONNECTING | locked | waiting for the window, then session/open |
| SYNCED | open | last save acked |
| PROBING | open, at most 5 s | one upload failed (3 s timeout); one immediate retry (2 s) |
| LOCKED | read-only | retry failed; WAL keeps non-edit events; background retry 1 s, 2 s, 4 s, 8 s, 10 s cap, pings continue |
| RESYNC | read-only | contact back: fetch held head, upload the contiguous pending range |
| FINALIZED | none | server said so; show the receipt-only page |

LOCKED to RESYNC to SYNCED only when the server acks the pending range, the session is not
finalized, and `T <= end_ms + drain_ms`. Text typed before the lock stays in the editor
buffer and a local draft file (never evidence) and is saved normally after resync, so
nothing typed before the lock is lost. Worst case of unsaved typing at the moment of lock is
about `save_interval_ms` plus the probe (7 s with defaults). Typing during LOCKED is
impossible by construction. The banner always shows "Last saved at HH:MM:SS" from the last
ack and says that sync stopped, in calm wording.

Countdown: the client shows `remaining_ms` from the last ack or ping and counts down on a
monotonic clock (`process.hrtime` in the shell). Changing the system clock changes nothing.
Rollback: if local chain is shorter than the held head (restored disk, wiped WAL), the
server answers ROLLBACK. The client cannot continue; it needs an assessor-signed TRANSFER
(v1 section 9).

## 10. Time and grace
Definitions: a **contact** is any accepted session/open, batch or ping. `t_last` is the
server_ms of the last contact. Subtractions: **server dark** intervals (section 7) and
assessor-signed **incident** documents (below).

Effective gap at time T: `gap = (T - t_last) - subtracted`, where `subtracted` is the
overlap of `[t_last, T]` with dark and incident intervals.

Rules (a pure function of `t_last`, the closed-outage total, the config and T):
1. A gap larger than `outage_threshold_ms` is an **outage**. When it closes (next contact)
   a CONTACT_GAP journal entry records `gross_ms`, `subtracted_ms`, `counted_ms = gross - subtracted`.
2. `used` = sum of `counted_ms` over closed outages. `remaining = outage_total_ms - used`.
3. An open outage expires at `E = t_last + min(outage_cap_ms, remaining) + (overlap already subtracted)`
   (the subtracted time does not burn budget).
4. Deadline `D = end_ms`. If `E >= D + drain_ms`, the window end wins.
5. At any evaluation instant `T > E`, the session is finalized **GRACE_EXPIRED** with
   `finalized_ms = E`, `final_seq` = the highest seq with an ack whose `seen_ms <= t_last`.
   When it is evaluated (scheduler, next contact, receipt read) does not change the result.
6. `window_end`: at `D + drain_ms` with no submit, `finalized_ms = D + drain_ms`,
   `final_seq` = highest acked seq.
7. `submitted`: after SESSION_END is acked and all manifest blobs are present,
   `finalized_ms` = server time of that finalize call.
8. Contacts after finalization get 410 and a receipt-only response. Data arriving later
   is stored in `late_tail` (append-only), excluded from the submission, and reported as
   UNCONFIRMED_TAIL (NOTE) in events and seconds.

Incident document: canonical `{"body": {v, exam_id, from_ms, to_ms}, "sig"}`, assessor key,
domain `incident`. It marks a lab-wide fault (switch died, power cut) and is subtracted
from every session's gaps. Extending the end time needs a new signed config revision.

"Connected" in the UI means the last save was acked, not that the network is up.

## 11. Finalization and the FINAL receipt
Document: canonical `{"body": B, "sig": hex}`, sig by the roster server key, domain `final`.
Text form: `IMR2.` + base64url (no padding) of the document bytes. The `.imr2` file holds
the document bytes themselves. `receipt_id = sha256_hex(document bytes)`.

B fields (all required, ASCII keys):
`v` (2), `kind` ("final"), `exam_id`, `session_id`, `ws_id`, `candidate` (pseudonym),
`final_seq`, `head`, `manifest_sha256`, `file_count`, `submit_seq` (uint or null),
`reason` (submitted / window_end / grace_expired), `finalized_ms`, `last_confirmed_ms`,
`outage_count`, `outage_total_ms`, `journal_head`, `roster_sha256`, `schedule_sha256`,
`paper_sha256`, `server_id`.

Student and examiner get byte-identical files, shown with the same `receipt_id`. A match of
the two ids is the "two-party confirmed" flag (never a requirement for A2).

### 11.1 Verification, identical for student and examiner
1. Decode strictly: `IMR2.` prefix, base64url, at most 4096 chars, canonical form required
   (`loads(..., require_canonical=True)`), keys exactly `{body, sig}`, ASCII keys.
2. Body keys exactly as above, `v` = 2, `kind` = "final", hashes 64 lowercase hex.
3. Signature verifies under the server key for `server_id` in the PINNED roster.
4. `exam_id`, `roster_sha256` and `paper_sha256` match the pinned roster.
5. Submission match: recompute the manifest from the files held, `sha256_hex(manifest)`
   equals `manifest_sha256`, `file_count` equals, and every file hash equals its manifest entry.
   Student uses the local submission folder; examiner uses the exported blobs.
6. With evidence: the chain event at `final_seq` hashes to `head`; SUBMIT's `manifest_sha256`
   equals the receipt's; ack anchors cover `final_seq`; `journal_head` is in the journal chain.
7. Always print: "A valid receipt shows that the server key signed these facts. It does not
   show who was at the keyboard, and it is only as trustworthy as the server key and the
   schedule the assessor signed."

## 12. Verifier and assurance (delta)
- **A2** now means: A1, plus a valid FINAL whose `head` is the hash of the event at
  `final_seq` in a chain signed by the seat's key. A chain ending without SESSION_END is
  accepted only when FINAL says `grace_expired` or `window_end` (NOTE END_WITHOUT_SESSION_END);
  otherwise it is TRUNCATED as in v1.
- Verdicts unchanged. A new report section, **Conduct flags**, never moves a verdict.

New findings:
| Code | Severity | Meaning |
|---|---|---|
| FINAL_BAD_SIG | SUSPECT | FINAL not signed by a roster server key |
| FINAL_HEAD_MISMATCH | SUSPECT | chain event at final_seq does not hash to `head` |
| FINAL_MANIFEST_MISMATCH | SUSPECT | submitted files or SUBMIT event disagree with FINAL |
| ACK_CONTRADICTS_LOG | SUSPECT | a server-signed ack held by the student disagrees with the exported log |
| JOURNAL_BREAK | SUSPECT | journal chain broken or not covering `journal_head` |
| SCHEDULE_MISMATCH | SUSPECT | `schedule_sha256` is not a signed config revision |
| WINDOW_VIOLATION | SUSPECT | an acked batch outside the window per journal times |
| CHAIN_PAST_FINAL | SUSPECT | an event acked after finalization is inside the submission |
| UNCONFIRMED_TAIL | NOTE | data delivered after finalization, excluded |
| SYNC_GAP | NOTE | outage counted against the budget |
| GRACE_EXPIRED | NOTE | session finalized by the grace rule |
| END_WITHOUT_SESSION_END | NOTE | see A2 |
| SERVER_DARK_SUBTRACTED | NOTE | server-dark time removed from gaps |
| INCIDENT_SUBTRACTED | NOTE | examiner-declared incident removed from gaps |
| OFFLINE_FALLBACK | NOTE | session used the LAN witness path |
| CLIPBOARD_BLOCKED | FLAG | count and total length of blocked clipboard actions |
| FOCUS_LOST_LONG | FLAG | one absence longer than 10 s (guess) |
| FOCUS_LOST_MANY | FLAG | more than 5 absences (guess) |
| UNAPPROVED_BUILD | FLAG | `agent_sha256` not in `approved_builds` (self-report) |

Wording rule stays: TAMPER_SUSPECTED means "evidence inconsistent, human review required".
Flags are worded "for human review" and never use "cheating".

Clock checks (v1 section 13) keep running, but offset is now measured against server
`seen_ms` in acks. On Windows `boot_id` is per-process, so an agent restart appears as a
new boot; that yields notes only.

## 13. Shell, clipboard and focus (what we claim)
| Behaviour | Claim |
|---|---|
| Copy, cut, paste inside the editor | blocked; event records action, length, time |
| Paste from outside the editor | blocked in the exam window only |
| Window loses focus, hidden or minimized | detected and flagged; not prevented |
| Alt-Tab, Win key, another device, another monitor | not prevented; out of scope |
| Clipboard content, window titles, other apps | never read, never stored |

## 14. Languages and evaluation
Per-language adapter, selected from `langs`:
`{lang, ext, probe_argv, build_argv|null, run_argv, limits}`. A build emits BUILD_END;
every run emits RUN_START (with `lang`, `toolchain`) and RUN_END. Compiled outputs are not
hashed (not reproducible); source hash plus toolchain id identify what ran.
In-exam runs are practice only. **Evaluation** is examiner-side after export: a deterministic
harness over the manifest and blobs, outside this spec. The lab machine needs the toolchains
installed; the app reports a missing toolchain at probe time and does not install anything.
Resource limits: POSIX rlimits on Linux; Windows Job Objects (memory, process count, time).

## 15. Storage contract (non-normative)
Tables: `exams`, `rosters`, `configs`, `incidents`, `sessions`, `events`, `batches`, `acks`,
`blobs` (content-addressed), `journal`, `finals`, `late_tail`, `ticks`.
- `events`: primary key `(session_id, seq)`, columns `hash`, `body bytea`, `received_ms`
  default `now()`. `BEFORE INSERT` trigger: `prev` equals the stored hash at `seq-1`, and
  `digest('immutable/v1/event' || 0x00 || body, 'sha256')` equals `hash`.
- `events`, `batches`, `acks`, `journal`, `finals`, `late_tail`: UPDATE and DELETE rejected
  by trigger and revoked. `sessions` is mutable, so the verifier derives state from the
  journal and never trusts that row.
- RLS denies anon and authenticated everywhere. Only the Edge Functions (service role) write.
- A database superuser can disable triggers. Detection comes from chain re-verification,
  student-held acks, the FINAL signature and the journal head, not from the triggers.

## 16. Offline fallback
Server unreachable for the whole exam (or the venue is isolated): the v1 path applies
unchanged (LAN witness, `IMR1.` receipt, A0/A1/A2 per v1). The sessions are labelled
OFFLINE_FALLBACK. The claim "online-first with graceful failure" holds only to the extent
the fallback was exercised in tests.

## 17. Code deltas this spec implies
`hashing.DOMAINS` + 4 domains; `policy.SCHEMAS` per 6.1 and a v2 path check;
`roster` accepts `servers`; new `examconf.py`, `journal.py`, `final.py` (issue and validate);
`findings.py` + codes above and a FLAG severity; `verifier.py` A2 and END_WITHOUT_SESSION_END;
`courier.py` target switch (server vs witness); `clock.py` Windows boot id (optional).
