# Threat model v0

Every attack test links back to a row ID here. Update this file before code.

## Assets
| ID | Asset |
|----|-------|
| A1 | Submitted artifacts (what the student handed in) |
| A2 | Completeness and order of the event history |
| A3 | Binding of seat, key and candidate |
| A4 | Time evidence (when things happened, relative order) |
| A5 | The honest student's ability to rebut a dispute |

## Actors
| ID | Actor | Capability |
|----|-------|-----------|
| X1 | Student | Admin/root on own workstation. Can read the workstation key. |
| X2 | Lab assistant | Physical access, can reboot, restore, delete files. May be sloppy or malicious. |
| X3 | LAN attacker | Read, drop, delay, replay, reorder packets. Cannot break crypto. |
| X4 | Assessor-side insider | Can delete or edit data after ingest. |
| X5 | Honest faults | Power loss, dead RTC battery, NTP step, suspend/resume, VM pause. |

## Trust anchors
- Assessor roster key (created before the exam, trusted for the exam).
- Witness key, if a witness is present.
- Exam paper hash, recorded before the exam starts.

## Threats
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
| T13 | Restore-on-reboot wipes the WAL | X2 X5 | A2 | Yes | `WalMissing` on a seat that already had a session. Persistent evidence volume required. |
| T14 | Student kills the agent, or runs it as the same OS user and reads the key | X1 | A2 | Partly | Silence shows as a heartbeat gap. Unanchored tail is reported (T3). Separate OS user recommended. |
| T15 | Student keeps work in files we cannot fingerprint (symlink, over 2 MiB, odd name) | X1 | A1 | Visible to the student | Listed in `skipped` and shown in the UI, never silently dropped. They are absent from the manifest by design. |
| T16 | One machine image (and key) cloned across seats | X2 | A3 | Yes | DUPLICATE_KEY. Keys are generated at enrollment, never in the image. |
| T17 | Student moves to a better machine mid-exam without authorisation | X1 | A3 | Yes | A chain on an unenrolled seat or key is UNKNOWN_SEAT / KEY_NOT_ENROLLED; a TRANSFER without the assessor's signature for this exact seat and key is TRANSFER_INVALID. |
| T18 | Transfer used to reset or hide history | X1 X2 | A2 | Yes | The signed from_last_seq and from_head pin where the old chain ends. Writing past it, a different head, or a missing tail is TRANSFER_MISMATCH. |
| T19 | Assessor key stolen or a roster swapped before the exam | X4 | A3 | No | Out of scope (stated). Mitigation is organisational: fingerprint printed on the envelope, roster id recorded in every SESSION_START so a late swap is visible as two different roster ids. |




## Evidence assurance levels
- **A0** self-consistent only. Proves little against a root attacker.
- **A1** an outside holder saw checkpoints up to seq N. Everything after N is the unanchored tail.
- **A2** A1 plus the student receipt matches the final head. The tail is closed.

## Out of scope, stated openly
Remote-solver cheating, assessor key compromise before the exam, student and
witness-operator collusion, hardware keyloggers, legal admissibility, any
surveillance.

## TODO
Map the seven failure tests named in the PS onto T-rows when B7 starts.
