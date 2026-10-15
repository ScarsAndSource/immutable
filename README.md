# Immutable

A log that someone else signed.

Offline practical exams fail in boring ways: power cuts, frozen machines, a lab
assistant who "cleaned up". Immutable records coarse, non-surveillance events
on each workstation, chains and signs them, has a witness on the lab LAN
countersign the heads, and gives the assessor a verifier that says plainly what
is **proven**, what is **suspicious**, and what is **unprovable**.

It never records keystrokes, screens, cameras or biometrics. That is enforced in
code (`policy.py`), not just promised.

It is tamper-*evident*, not tamper-proof. Read `docs/THREAT_MODEL.md` first.

## Quickstart

    pip install -e .
    python tools/gen_vectors.py
    pytest

## Web Console & Interactive Frontend

Launch the unified web console:

    python tools/web_console.py --open

The console serves the complete interactive frontend at `http://127.0.0.1:8000`:

1. **Candidate Attestation Folio (`01 // Attestation`)**:
   - Official pre-exam disclosure (§01-PRE)
   - Bilingual support (English / हिंदी)
   - Plain-English breakdown of recorded events vs. strictly unrecorded telemetry
   - Cryptographic station integrity affirmation

2. **Candidate Workstation & Live Ledger (`02 // Workstation`)**:
   - Live workspace file manager with auto-committed SHA-256 fingerprints
   - Sandboxed code runner with wall-clock execution limits and stdout/stderr capture
   - Real-time immutable hash chain timeline (`SESSION_START`, `BOOT`, `FILE_SAVE`, `RUN_START`, `RUN_END`, `CHECKPOINT`, `HEARTBEAT`, `SUBMIT`)
   - Manual Merkle checkpointing and LAN witness flushing

3. **Archival Folio Receipt (`03 // Receipt`)**:
   - Official countersigned examination submission slip
   - Cryptographic QR proof matrix and raw verifiable voucher digest
   - Station seat binding, witness co-signature count, and physical perforation styling
   - One-click slip copy and print layout

4. **Assessor Audit & Verifier Console (`04 // Assessor Audit`)**:
   - Live reconciliation of evidence stores
   - Tri-partition verdict report:
     - **What is Proven** (`+` statements: anchored bounds, corroborated saves)
     - **What is Suspicious** (`!` findings: missing ranges, corrupted hashes, gap alerts)
     - **What Cannot Be Proven** (`?` statements: administrator boundaries, offline intervals)
   - Full rendered plain-text case notes

5. **Tamper Lab Workbench (`05 // Tamper Lab`)**:
   - Interactive runner for all 37 threat scenarios (Controls, Deletions, Rollbacks, Clock Shifts, Replays, Seat Swaps, Power Cuts, Forks, Key Theft)
   - One-click adversarial trials with live verification results and suspect code inspection

6. **LAN Witness Monitor (`06 // LAN Witness`)**:
   - Real-time LAN witness telemetry: held workstation sequence commitments, contact gaps, and equivocation conflict refusals

### Design Philosophy
- **Minimal & Dignified**: Built with an archival, legal-folio aesthetic.
- **Strictly Formal**: High-credibility typography (`Newsreader`, `Hanken Grotesk`, `JetBrains Mono`). Zero italics and zero background gradients.
- **No Online/Offline Dots**: State is communicated via formal monospaced status badges (`[CHAIN INTACT]`, `[LAN WITNESS · 14 CO-SIGNATURES]`) rather than glowing circles.
