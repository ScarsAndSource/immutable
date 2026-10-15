# Demo script

Timings are estimates until rehearsed. Rehearse against `docs/REHEARSAL.md`.

## 90-second pitch

A final score cannot explain a disputed practical run, and central logging dies when the lab
network does. Immutable fixes that without watching anyone. Each workstation signs a
hash-chained log of coarse events: files saved, programs run, hashes only. A witness on the
lab LAN countersigns the heads. The student leaves with a receipt. Afterwards the verifier
tells the examiner three things: what is proven, what looks tampered, and what cannot be
proven at all. That third list is the point. We never say tamper-proof; we say exactly where
the evidence stops. No keystrokes, no screens, no cameras, and that is enforced in code, not
promised on a slide.

## 3-minute run of show (demo mode)

Start: `python tools/web_console.py --mode demo --open`

| Time | Screen | Say and do |
|---|---|---|
| 0:00 | `01 // Attestation` | "This is exactly what is recorded, and what is not." Toggle Hindi once. Point at `docs/POLICY.md`: generated from the code |
| 0:30 | `02 // Workstation` | Save a file, run it, press checkpoint, flush. Point at the witness tag and the chain timeline |
| 1:00 | Terminal | `python tools/lab_agent.py ...`, work, `kill -9`, start again: the ledger shows RECOVERY. Say it is a process kill; the real power-off result is in `docs/EVALUATION.md` |
| 1:30 | `05 // Tamper Lab` | Run `C0` (control, clean) then `D1` (deletion): detected. Run a key-theft scenario (group 9) and read the expected outcome off the screen: the grey "cannot be proven" is the honest case |
| 2:15 | `03 // Receipt` | Submit. Show the receipt and QR. "Signed by this seat's key." |
| 2:35 | `04 // Assessor` | Paste the receipt into the checker: checks tick. Show the three-way report |
| 2:55 | Terminal | `python tools/validate_receipt.py ...` offline, no network, same answer |
| 3:00 | Close | "Open specification, reference implementation, honest numbers." |

Do not promise an outcome for any scenario you have not just seen on screen.

## If something breaks

1. Backend dead (the page shows no live data): restart the console with a fresh `--dir`.
2. Page unstyled: the vendored assets are missing; run `python scripts/preflight.py`.
3. Anything else: switch to the pre-captured outputs in `demo/fallback/` and the recorded video.
4. Say what happened. Never narrate a broken screen as working.

## Words to avoid

"Tamper-proof", "unhackable", "cheating" (say "evidence inconsistent"), "blockchain", "AI".
Say "tamper-evident", "proven", "cannot be proven".
