# Architecture

## Picture

    student workstation                 lab LAN                exam office (offline)
    +-----------------------+      +------------------+     +---------------------------+
    | editor / sandbox run  |      | witness node     |     | roster_tool   (ceremony)  |
    |        |              |      | one hash per     |     | store  (SQLite)           |
    | agent --WAL--chain ---+----->| (session,seat,   |---->| reconcile -> case file    |
    |   signed batches,     | pings|  seq); cosigns   | copy| verifier  -> verdicts     |
    |   checkpoints         |      +------------------+     | validate_receipt          |
    |   receipt (IMR1.)     |                               +---------------------------+
    +-----------------------+

## Trust anchors

1. The **assessor key**, created before the exam and pinned by every verifier. A roster is
   never trusted because it is embedded in the evidence.
2. The **witness keys** listed in that roster.
3. The **exam paper hash** recorded in the roster before the exam.

## Data path

1. Workstation agent writes each event to a write-ahead log (fsync, framed, CRC). Only the
   final record may be torn. Anything else is a finding.
2. Events are chained: each carries the hash of the one before it, and the exam, session,
   seat and position are inside the signed bytes, so a batch cannot be replayed elsewhere.
3. Events are sealed into signed batches with a Merkle root. Checkpoint events let a
   verifier check long logs quickly.
4. The courier sends batches to the witness, which cosigns the head it saw and keeps one
   hash per (session, seat, seq). A batch that disagrees with what it holds is refused whole.
5. On submit the agent freezes files by hash, writes a canonical manifest, emits SUBMIT and
   SESSION_END, and signs the student receipt (`IMR1.` text, see FORMAT section 14).
6. The assessor ingests evidence and witness copies. Ingest is idempotent; reconciliation
   is deterministic, so any arrival order gives the same case-file hash.
7. The verifier judges each seat and reports **proven**, **suspicious** and **cannot be
   proven**, with an assurance level.

## Anchors and assurance

An anchor says: holder H saw, by its own clock, that seat S had an event with hash X at
position N. The chain makes one anchor pin the whole prefix 0..N.

| Level | Meaning |
|---|---|
| A0 | Self-consistent only. No outside holder saw any head |
| A1 | An outside holder saw a prefix. The rest is the unanchored tail |
| A2 | A1, plus a receipt that matches the final head of a closed session |

A receipt alone is never an outside holder: whoever holds the key can sign one.

## Verdicts and findings

Verdicts: `TAMPER_SUSPECTED`, `NO_EVIDENCE`, `SELF_CONSISTENT_ONLY` (A0), `ANCHORED`
(A1 or A2). Only findings of severity SUSPECT move a verdict; NOTE findings never do. The
wording for TAMPER_SUSPECTED is "evidence inconsistent, human review required", never
"cheating".

## Clocks

Each event carries wall time, monotonic boot time and a boot id. Inside one boot, wall and
boot time must agree. Across reboots the time is reported as uncertain, bounded above by an
outside holder's clock. Absolute wall time is never alarmed on, because lab clocks are wrong.

## Determinism

Canonical JSON only: sorted keys, strings, integers, booleans, null, lists and objects; no
floats; NFC text; duplicate keys rejected. The case file has no generation time and no
arrival order. `tools/shuffle_check.py` shuffles inputs and adds duplicates to prove it.

## Console (demo)

`server.py` is one process playing student, witness, assessor and tamper lab so a judge can
see everything on one screen. It is a demonstrator, not the deployment shape. See
`docs/SECURITY_REVIEW.md` for how it is fenced.
