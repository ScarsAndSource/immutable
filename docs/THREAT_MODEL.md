# Threat model v1 (adds server-anchored mode)

Every attack test links back to a row ID here. Update this file before code.

## Assets
| ID | Asset |
|----|-------|
| A1 | Submitted artifacts (what the student handed in) |
| A2 | Completeness and order of the event history |
| A3 | Binding of seat, key and candidate |
| A4 | Time evidence (when things happened, relative order) |
| A5 | The honest student's ability to rebut a dispute |
| A6 | The exam window and schedule |
| A7 | The final receipt |

## Actors
| ID | Actor | Capability |
|----|-------|-----------|
| X1 | Student | Admin/root on own workstation. Can read the workstation key. |
| X2 | Lab assistant | Physical access, can reboot, restore, delete files. May be sloppy or malicious. |
| X3 | LAN attacker | Read, drop, delay, replay, reorder packets. Cannot break crypto. |
| X4 | Assessor-side insider | Can delete or edit data after ingest. |
| X5 | Honest faults | Power loss, dead RTC battery, NTP step, suspend/resume, VM pause, lab-wide network loss. |
| X6 | Backend operator | Superuser on the database. Can disable triggers and edit rows. Cannot see the server signing key unless they also own the project secrets. |

## Trust anchors
- Assessor roster key (created before the exam, trusted for the exam).
- Witness key, if a witness is present.
- Server key listed in the roster (v2 mode).
- Exam paper hash and signed exam config, recorded before the exam starts.

## Threats (v1)
| ID | Threat | Actor | Asset | Detectable? | Notes |
|----|--------|-------|-------|-------------|-------|
| T1 | Edit an event in place | X1 X2 | A2 | Yes | Chain break + Merkle mismatch |
| T2 | Delete a middle event | X1 X2 | A2 | Yes | Seq gap + chain break |
| T3 | Truncate the tail | X1 X2 | A2 | Only up to the last anchor | Beyond the last witness-held head it is unprovable. Report the unanchored tail in events and seconds. |
| T4 | Forge a whole session from scratch with the stolen key | X1 | A2 A3 | No on its own | Bounded by witness cosignatures. Stated limit, never hidden. |
| T5 | Replay a batch across session, exam or seat | X3 | A2 A3 | Yes | exam_id, session_id, ws_id, seq are inside signed bytes |
| T6 | Fork: same (session, seq), different content | X1 X3 | A2 | Yes | Reconciler flags, both branches kept |
| T7 | Clone one key to many seats (imaging) | X2 | A3 | Yes | Duplicate-key check against roster |
| T8 | Backdate or reorder using the clock | X1 | A4 | Partly | Only wall vs boottime inconsistency inside one boot. Never alarm on absolute wall time. |
| T9 | Smuggle surveillance data through event fields | any | privacy | Yes | Schema allow-list rejects unknown types and keys |
| T10 | Malformed or hostile input at ingest | X3 | all | Yes | Size and depth limits, strict parse, no float, no dup keys |
| T11 | Benign fault read as an accusation | X5 | A5 | n/a | Benign faults yield NOTES, never TAMPER_SUSPECTED |
| T12 | Disk acknowledges fsync but loses the data (write-cache lie, VM layer) | X5 | A2 | Detected, not prevented | Shows up as a recovered chain shorter than a witness-held head. State the fsync-honesty assumption. |
| T13 | Restore-on-reboot wipes the WAL | X2 X5 | A2 | Yes | `WalMissing` on a seat that already had a session. Persistent evidence volume required. In v2 the server answers ROLLBACK. |
| T14 | Student kills the agent, or runs it as the same OS user and reads the key | X1 | A2 | Partly | Silence shows as a heartbeat gap. Unanchored tail is reported (T3). Separate OS user recommended. |
| T15 | Student keeps work in files we cannot fingerprint (symlink, over 2 MiB, odd name) | X1 | A1 | Visible to the student | Listed in `skipped` and shown in the UI, never silently dropped. They are absent from the manifest by design. |
| T16 | One machine image (and key) cloned across seats | X2 | A3 | Yes | DUPLICATE_KEY. Keys are generated at enrollment, never in the image. |
| T17 | Student moves to a better machine mid-exam without authorisation | X1 | A3 | Yes | A chain on an unenrolled seat or key is UNKNOWN_SEAT / KEY_NOT_ENROLLED; a TRANSFER without the assessor's signature for this exact seat and key is TRANSFER_INVALID. |
| T18 | Transfer used to reset or hide history | X1 X2 | A2 | Yes | The signed from_last_seq and from_head pin where the old chain ends. Writing past it, a different head, or a missing tail is TRANSFER_MISMATCH. |
| T19 | Assessor key stolen or a roster swapped before the exam | X4 | A3 | No | Out of scope (stated). Mitigation is organisational: fingerprint printed on the envelope, roster id recorded in every SESSION_START so a late swap is visible as two different roster ids. |
| T20 | Witness equivocates or is fed two histories | X1 X3 | A2 | Prevented at the witness | One hash per (session, seat, seq); conflicting batches refused whole and logged as authenticated refusals. |
| T21 | Witness down for a stretch | X5 | A2 | Visible | The stretch is anchor gap and unprotected exposure in the coverage line; nothing is faked. |
| T22 | Student stops the courier or deletes local anchors | X1 | A2 | Partly | Witness contact record shows the silence; the witness keeps its own anchors and batch copies. |
| T23 | Witness operator colluding with a student | X1 X4 | A2 | No | Out of scope (stated). |
| T24 | Unauthorized seat gets anchors via a forged transfer | X1 | A3 | Yes | The witness binds a key only through an assessor-signed TRANSFER naming that exact seat and key. |
| T25 | Replayed ping fakes liveness | X3 | A4 | Yes | boot_ns must increase within a boot_id (replay protection). |

## Threats (v2, server-anchored mode)
| ID | Threat | Actor | Asset | Detectable? | Notes |
|----|--------|-------|-------|-------------|-------|
| T26 | Edit or delete rows in the plain database after the exam | X4 X6 | A1 A2 A7 | Yes, if the student holds acks or a FINAL | Append-only triggers stop casual edits only. Detection: chain re-walk, ACK_CONTRADICTS_LOG, FINAL_HEAD_MISMATCH, JOURNAL_BREAK. A backend operator who also holds the signing key is T47. |
| T27 | Change the workstation clock to stretch or shrink the window | X1 | A6 A4 | Prevented | Window is enforced on database `now()`; countdown is monotonic. Client wall time only yields CLOCK_OFFSET notes. |
| T28 | Retry, reconnect or restored state overwrites newer data | X5 X1 | A2 A1 | Prevented | `unique (session_id, seq)`; same hash is a no-op; different hash is FORK_REJECTED; lower seq is STALE. |
| T29 | Outage farming: block the network on purpose to gain unconfirmed time | X1 | A2 | Bounded, not prevented | Editor locks on a failed save plus retry; per-outage cap and total budget; exposure is at most the cap. Stated limit. |
| T30 | Ambiguity when grace expires (who decides, when, with which data) | X5 | A5 A7 | Yes | Pure function of `t_last`, budget and config; FINAL names the reason; same answer whenever evaluated. |
| T31 | Work typed between connection loss and lock is lost | X5 | A5 | Mitigated | Buffer and local draft survive; saved after resync. Crash inside the lock window can lose at most about 7 s of typing. |
| T32 | Receipt altered or forged | X1 X4 | A7 | Yes | Server signature over canonical bytes; strict canonical decode; pinned roster key. |
| T33 | Receipt does not match what was submitted (file swapped after the fact) | X4 X6 | A1 A7 | Yes | Manifest hash and per-file hashes recomputed by both parties; FINAL_MANIFEST_MISMATCH. |
| T34 | Over-claiming clipboard and tab control | any | credibility | n/a | Section 13 of FORMAT_V2: blocked vs flagged vs not prevented, stated everywhere. |
| T35 | Bypass via second device, OS shortcut, VM or remote desktop | X1 | A5 | No | Out of scope (stated). Focus loss is flagged only where the shell can see it. |
| T36 | Same student or seat opens two sessions at once | X1 | A3 | Yes | One active session per seat; second gets SESSION_REJECTED already_active. |
| T37 | Direct database access with the public client key | X1 X3 | A2 | Prevented | RLS denies all; writes only through Edge Functions. |
| T38 | Service-role key or server signing key leaks (client bundle, repo, logs) | any | A7 | No once leaked | Secrets only in Edge Function config; never in the shell; key rotation means a new roster before the next exam. |
| T39 | Examiner changes the schedule mid-exam to favour someone | X4 | A6 | Yes | Config is immutable per `rev`; every revision journaled; receipt names `schedule_sha256`; SCHEDULE_MISMATCH. |
| T40 | Backend outage looks like a student outage | X5 | A5 | Handled | Server dark time (tick holes) is subtracted from every gap; SERVER_DARK_SUBTRACTED note. |
| T41 | Hash differs by platform (CRLF, BOM, path separator) | X5 | A1 | Prevented | Raw-byte hashing, no conversion; paths in 6.3; golden vectors F1 to F3. |
| T42 | Hostile Windows filenames (device names, ADS, trailing dot, case collisions) | X1 | A1 | Visible | Rejected into `skipped`; rules apply on all platforms. |
| T43 | Student runs a modified exam app | X1 | A2 | Self-report only | `agent_sha256` checked against `approved_builds`, UNAPPROVED_BUILD is a FLAG. A root user can spoof it. Stated. |
| T44 | Flooding the server (quota, cost, rate) | X1 X3 | A2 | Bounded | Per-session batch and blob caps, 429; caps are guesses to be measured. |
| T45 | Data arriving after finalization changes the submission | X1 X5 | A1 A7 | Prevented | 410 plus `late_tail`; excluded; UNCONFIRMED_TAIL note. |
| T46 | Session opened by someone without the enrolled seat key | X1 X3 | A3 | Yes | Signed open request, seat key from the pinned roster; SESSION_REJECTED not_enrolled. |
| T47 | Backend operator holds the server key and edits history and signs a new FINAL | X4 X6 | A2 A7 | No | Out of scope (stated). Mitigation: student-held acks and the original receipt disagree with the new one. |
| T48 | Lab-wide network failure burns every student's grace budget | X5 | A5 | Handled | Assessor-signed incident document subtracted from all gaps; INCIDENT_SUBTRACTED note. |

## Evidence assurance levels
- **A0** self-consistent only. Proves little against a root attacker.
- **A1** an outside holder (witness or server) saw checkpoints up to seq N. Everything after N is the unanchored tail.
- **A2** A1 plus a final record that matches the chain. In v1 offline mode: the student receipt matches the final head. In v2: a valid server-signed FINAL whose `head` matches the chain event at `final_seq`.

A receipt forged by a root user is caught only by an outside anchor or the assessor's copy of the log. That is the reason A2 needs both.

## Out of scope, stated openly
Remote-solver cheating, assessor key compromise before the exam, student and
witness-operator collusion, backend operator who also holds the server key (T47),
hardware keyloggers, second devices, legal admissibility, any surveillance.

## The seven PS failure tests mapped to rows
| PS test | Rows |
|---|---|
| Log deletion | T2, T3, T26 |
| Rollback | T3, T12, T13, T28 |
| Clock manipulation | T8, T27, T40 |
| Replay | T5, T25, T28 |
| Workstation swap | T7, T16, T17, T18, T36, T46 |
| Interrupted power | T12, T13, T14, T31 |
| Sync conflicts | T6, T20, T28, T45 |

## Detection map (finding codes that answer each threat)
| Threat | Finding codes |
|--------|---------------|
| T1 edit in place | BATCH_DEFECT, LINK_BREAK, CHECKPOINT_BAD, ANCHOR_CONFLICT |
| T2 delete middle | MISSING_RANGE, LINK_BREAK |
| T3 truncate tail | TRUNCATED, ROLLBACK (only up to the last anchor; beyond it: UNANCHORED_TAIL statement) |
| T4 forge from scratch | ANCHOR_CONFLICT, TRUNCATED. With no anchor: NO_ANCHOR statement, never a green tick |
| T5 replay / T10 hostile input | MALFORMED, BAD_SIGNATURE, WRONG_EXAM, FOREIGN_BATCH (all NOTE, cannot frame anyone) |
| T6 fork | FORK |
| T7 / T16 cloned key | DUPLICATE_KEY, KEY_NOT_ENROLLED |
| T8 clock | CLOCK_BACKWARD, BOOT_REVISIT (SUSPECT); CLOCK_STEP, CLOCK_OFFSET, SILENCE (NOTE) |
| T12 fsync lied | ROLLBACK or TRUNCATED against an outside holder |
| T13 wiped WAL | BAD_START or MISSING_RANGE, plus TRUNCATED with an anchor |
| T14 agent killed | SILENCE, RECOVERED, unanchored tail statement |
| T15 unfingerprinted files | SUBMISSION_GAP |
| T17 unauthorised swap | UNKNOWN_SEAT, KEY_NOT_ENROLLED, TRANSFER_INVALID |
| T18 transfer abuse | TRANSFER_MISMATCH |
| T19 roster swap | ROSTER_MISMATCH |
| T26 backend edit | ACK_CONTRADICTS_LOG, FINAL_HEAD_MISMATCH, JOURNAL_BREAK |
| T29 / T30 / T40 / T48 outages and grace | SYNC_GAP, GRACE_EXPIRED, SERVER_DARK_SUBTRACTED, INCIDENT_SUBTRACTED (NOTE) |
| T32 / T33 receipt | FINAL_BAD_SIG, FINAL_MANIFEST_MISMATCH |
| T34 / T35 / T43 conduct | CLIPBOARD_BLOCKED, FOCUS_LOST_LONG, FOCUS_LOST_MANY, UNAPPROVED_BUILD (FLAG, never a verdict) |
| T39 schedule | SCHEDULE_MISMATCH, WINDOW_VIOLATION |
| T45 late data | UNCONFIRMED_TAIL (NOTE), CHAIN_PAST_FINAL (SUSPECT) |
