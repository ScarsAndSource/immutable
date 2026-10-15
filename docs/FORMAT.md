# Immutable byte format, v1

Anything two machines must agree on lives here. If code and this file disagree,
the code is wrong.

## 1. Canonical JSON
- UTF-8, no whitespace, no trailing newline, object keys sorted by **code point**.
  (Python's default. JS `sort()` compares UTF-16 units and differs for astral
  characters, so the JS side must compare by code point.)
- Values: `null`, booleans, strings, arrays, objects, integers.
- **No floats.** Integers must satisfy |n| <= 2^53 - 1 (JS-safe).
- Strings must already be **NFC**. The encoder rejects non-NFC input instead of
  silently rewriting it. No lone surrogates.
- Parser rejects duplicate keys, NaN/Infinity, floats, depth > 32, size over limit.
- Paths: POSIX relative, NFC, no `..`, no leading `/`, no backslash, no NUL.
- Hashes: 64 lowercase hex. Signatures: 128 lowercase hex. Public keys: 64 hex.

## 2. Domain separation
Every hash and every signature input is
`"immutable/v1/" || domain || 0x00 || data`.
Domains: `event`, `batch`, `merkle.leaf`, `merkle.node`, `merkle.empty`, `key`,
`checkpoint`, `roster`, `receipt`, `cosign`, `transfer`.
File contents are the one exception: artifact hashes are plain SHA-256 of raw
bytes so anyone can check them with `sha256sum`.

## 3. Event
Body (all fields required, no others):
`v, exam_id, session_id, ws_id, seq, prev, type, wall_ms, boot_ns, boot_id, data`
- `seq` starts at 0, +1 each event. `prev` is the previous event's hash;
  genesis `prev` is 64 zeros.
- `wall_ms`: Unix ms. `boot_ns`: CLOCK_BOOTTIME ns. `boot_id`: per-boot identifier.
- Event hash = `H(event, canonical(body))`. `prev` is inside the body, so the
  hash chains.
- `data` must match the per-type schema in `policy.py`. Unknown types and
  unknown keys are rejected. That is the no-surveillance guarantee.
- Identifiers (exam, session, ws): `[A-Za-z0-9._-]{1,64}`. Candidate identity is
  never in an event; it is bound through the roster.

## 4. Batch
`{"header": H, "events": [body...], "sig": hex}`
Header: `v, exam_id, session_id, ws_id, first_seq, last_seq, count, first_prev,
head, merkle_root, signer`
- `head` = hash of the last event. `merkle_root` = RFC 6962 tree over the event
  hashes in order (leaf and node prefixes via domains).
- `sig` = Ed25519 over `tagged("batch", canonical(H))` by the key `signer`.

## 5. Merkle
RFC 6962 shape: split at the largest power of two strictly below n. Leaf =
`H(merkle.leaf, raw event hash)`, node = `H(merkle.node, left || right)`,
empty = `H(merkle.empty, "")`. Proofs are bottom-up sibling lists.

## 6. Verification result
`verify_batch` returns a list of coded findings. An **empty list means
self-consistent (A0), not verified.** Only an outside anchor upgrades that.

## 7. Write-ahead log
Frame: `"CW" || len u32be || payload || crc32 u32be`, crc over `len || payload`,
payload = canonical event JSON (max 64 KiB). The hash chain is the integrity;
the CRC only makes torn writes recognisable.

Torn-tail rule: scan from byte 0, accept whole records with a good CRC. The first
rejected record is a TORN TAIL (truncate, emit RECOVERY) if it is a stub shorter
than a header, runs past EOF, is a zero-filled tail, or is CRC-bad and ends
exactly at EOF. Anything else (bad magic with data, CRC-bad with bytes after it,
a valid record that breaks the chain) is CORRUPT: recovery refuses, a human
decides.

Recovery appends a RECOVERY event `{last_good_seq, discarded_bytes}` to the
chain, sealed into a batch immediately. A reopen of an empty log emits nothing.

Acknowledged = fsynced. Only events at or below `durable_seq` may be sealed or
shown to a witness. Any write or fsync error fail-stops the log until recovery.

## 8. Evidence directory (one per session, per workstation)
    session.wal                      write-ahead log (section 7)
    ws.key                           0600 seed (keep off the student's account if you can)
    outbox/FFFFFFFF-LLLLLLLL.batch.json   sealed batches, contiguous, first_seq-last_seq
    submission/manifest.json         canonical: {v, exam_id, session_id, ws_id, files:[{path,sha256,size}]}
    submission/blobs/<sha256>        submitted file bytes, stored only under their hash

Event order guarantees: SESSION_START, BOOT first. A save always precedes the
RUN_START that uses it (the hash is of the exact bytes that executed). Submit is
FILE_SAVE* (if anything changed), CHECKPOINT, SUBMIT, SESSION_END. A RUN_START
`manifest_sha256` is plain SHA-256 of the manifest bytes.

## 9. Identity
Roster file = canonical `{"body": B, "sig": hex}`, sig = Ed25519 by `B.assessor`
over `tagged("roster", canonical(B))`. B: `v, exam_id, issued_ms, paper_sha256,
assessor, seats[{ws_id,pub,candidate|null}], witnesses[{witness_id,pub}]`.
Seats sorted by ws_id, witnesses by id, no duplicates. The assessor key, every seat
key and every witness key are pairwise distinct. Files must be canonical so the
roster id (`sha256_hex(file bytes)`, recorded as `SESSION_START.roster_sha256`) has
one representation. Candidates are pseudonyms; real identity never appears.

Enrollment request = canonical `{"body": {v, exam_id, ws_id, pub}, "sig"}`, sig by
`pub` under domain `enroll` (proof of possession).

Transfer statement S = `{v, exam_id, session_id, from_ws_id, from_last_seq,
from_head, to_ws_id, to_pub}`; token = `{"body": S, "sig"}` by the assessor, domain
`transfer`. The new chain's event 2 is TRANSFER `{from_ws_id, from_last_seq,
from_head, assessor_sig}`; `to_ws_id` is the event's ws_id and `to_pub` the batch
signer. A candidate follows the transfer; the old seat is retired and must not have
events past `from_last_seq`, and its event at that seq must hash to `from_head`.



