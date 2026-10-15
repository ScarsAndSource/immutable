# Immutable

A log that someone else signed.

Offline practical exams fail in boring ways: a power cut, a frozen machine, a lab
assistant who "cleaned up". Then a score is disputed and nobody can show what happened.
Immutable records coarse, non-surveillance events on each workstation, chains and signs
them, has a witness on the lab LAN countersign the heads, hands the student a receipt,
and gives the assessor a verifier that says plainly what is **proven**, what is
**suspicious**, and what **cannot be proven**.

It never records keystrokes, screens, cameras, microphones or biometrics. That is
enforced in code (`src/immutable/policy.py`), and `docs/POLICY.md` is generated from it.

It is tamper-**evident**, not tamper-proof. Read `docs/LIMITATIONS.md` before anything else.

## What it proves, and what it does not

| It can show | It cannot show |
|---|---|
| The log is one unbroken chain signed by the key enrolled for that seat | Who was sitting at the machine |
| Which events an outside holder (witness, assessor, receipt) saw | That the student had no outside help |
| That a deleted middle, a rewritten event, a replayed batch or a swapped seat is inconsistent | Anything about history no outside party ever saw, if the user had administrator rights |
| That a power cut left at most one torn record, and recovery said so | That wall-clock times are true; they are the machine's claims |

Assurance levels: **A0** self-consistent only. **A1** an outside holder saw a prefix; the
rest is the unanchored tail, reported in events and seconds. **A2** A1 plus the student
receipt matching the final head of a closed session.

## Quickstart

    pip install -e ".[qr]"          # [qr] adds segno for the receipt QR code (optional)
    python tools/gen_vectors.py
    python scripts/preflight.py
    python tools/web_console.py --open

Offline machines: `scripts/offline_install.sh prepare` once on a connected machine, then
`scripts/offline_install.sh install` on each lab machine. See `docs/DEPLOYMENT.md`.

## The three ways to run it

| Mode | What | Use it for |
|---|---|---|
| `tools/web_console.py --mode demo` | One process playing every role: student, witness, assessor, tamper lab | Demos and judging |
| `tools/web_console.py --mode exam` | Student pages only; assessor, witness and tamper-lab endpoints refuse | A student workstation UI |
| `tools/lab_agent.py` + `tools/witness_node.py` + `tools/assessor.py` | The real separation of roles, all file-based | A real lab |

## Repository map

    src/immutable/   core library: canon, hashing, keys, wal, chain, batch, merkle, roster,
                     agent, witness, courier, store, reconcile, verifier, receipt, policy
    tools/           command-line tools (roster ceremony, agent, witness, assessor, evaluation)
    lab/             the tamper lab: 37 scripted scenarios in 10 groups
    web/             the console UI
    docs/            FORMAT, THREAT_MODEL, ARCHITECTURE, POLICY, LIMITATIONS, DEPLOYMENT,
                     EVALUATION, DEMO_SCRIPT, JUDGE_QA, SECURITY_REVIEW, REHEARSAL
    scripts/         preflight, offline install, web vendoring, demo fallback capture
    vectors/         golden canonicalization and signature vectors for other implementations

## Command cheat sheet

    # exam office, before
    python tools/roster_tool.py assessor-init --out assessor.key
    python tools/roster_tool.py build --assessor-key assessor.key --exam EX1 --paper paper.pdf \
        --requests ./reqs --candidates candidates.txt --witness W1=<pub> --out roster.json

    # after the exam
    python tools/assessor.py verify --roster roster.json --assessor-pub <pub> EVIDENCE_DIR...
    python tools/validate_receipt.py --roster roster.json --assessor-pub <pub> \
        -f slip.txt --evidence EVIDENCE_DIR
    python tools/shuffle_check.py --roster roster.json --assessor-pub <pub> EVIDENCE_DIR...

## Status

Built: signed hash-chained events, WAL with torn-tail recovery, signed batches and Merkle
checkpoints, roster and transfers, duplicate-key detection, LAN witness with equivocation
refusal, courier, assessor store, deterministic reconciliation and case file, verifier with
three-way findings, clock checks and calibration, student receipt and validator, tamper lab,
false-alarm evaluation, web console.

Not built: Raspberry Pi witness, offline browser receipt validator, chained signed ingest
log, legal review, any pilot in a real institute. The prototype runs a simulated lab; the
crypto, recovery, witness and verifier are real code.
