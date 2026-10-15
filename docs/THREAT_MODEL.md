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
