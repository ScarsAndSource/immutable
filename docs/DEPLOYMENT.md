# Deployment

The web console is a demonstrator. A real lab uses the file-based tools below.

## 0. Prepare (one connected machine)

    scripts/offline_install.sh prepare      # wheels into vendor/wheels, web assets into web/vendor
    # copy the whole repository, vendor/ and web/vendor/ included, to the exam office

Build wheels on the same operating system, CPU and Python version as the lab machines.

## 1. Ceremony (exam office, offline)

    python tools/roster_tool.py assessor-init --out assessor.key
    python tools/witness_node.py init --out witness.key              # prints the witness public key

Keep `assessor.key` off every lab machine. Record the assessor **public** key somewhere
students cannot edit: every verifier pins it.

On each workstation, first start creates the seat key and prints its public key:

    python tools/lab_agent.py --exam EX1 --session S1 --ws WS01 \
        --workspace ./student_files --evidence ./evidence --paper ./paper.pdf
    python tools/roster_tool.py request --exam EX1 --ws WS01 --key evidence/ws.key --out WS01.req.json

Collect the `*.req.json` files, write `candidates.txt` (one `WS_ID PSEUDONYM` per line, no
real names), then:

    python tools/roster_tool.py build --assessor-key assessor.key --exam EX1 --paper paper.pdf \
        --requests ./reqs --candidates candidates.txt --witness W1=<witness-pub> --out roster.json
    python tools/roster_tool.py verify roster.json --assessor-pub <pub> --paper paper.pdf

Distribute `roster.json` to every workstation and to the witness.

## 2. Exam day

- **Witness** on a machine students cannot touch (a spare laptop):

      python tools/witness_node.py run --roster roster.json --assessor-pub <pub> \
          --key witness.key --id W1 --dir ./witness --port 9443

- **Workstations**: run the agent as above, with the witness address from `--help`.
- **Evidence volume must persist across reboots.** If the lab image restores itself on reboot,
  mount evidence on a separate disk or the seat will look like a missing log.
- Use your own switch or hotspot. Do not depend on venue Wi-Fi.

## 3. A student must move machines

    python tools/roster_tool.py transfer --assessor-key assessor.key --roster roster.json \
        --session S1 --from WS01 --last-seq <n> --head <hash> --to-request WS07.req.json --out t.json

The old seat is retired at `from_last_seq`; the new chain starts with the signed transfer.

## 4. After the exam (assessor, offline)

Copy each workstation's `evidence/` (`outbox/`, `submission/`, `receipt/`) and the witness's
`anchors/` and `batches/` to the exam office.

    python tools/assessor.py verify --roster roster.json --assessor-pub <pub> EVIDENCE_DIR... WITNESS_DIR
    python tools/shuffle_check.py   --roster roster.json --assessor-pub <pub> EVIDENCE_DIR... WITNESS_DIR

Exit code 1 means at least one session needs a human to look.

## 5. A disputed result

    python tools/validate_receipt.py --roster roster.json --assessor-pub <pub> \
        -f student_slip.txt --evidence EVIDENCE_DIR... WITNESS_DIR

A valid receipt plus A2 means the student's copy, the witness and the log agree.

## 6. When things go wrong

| Situation | What happens | What to do |
|---|---|---|
| Witness down for a stretch | The stretch is reported as unanchored tail | Restart it; nothing is lost, the courier retries |
| Power cut | Agent restart logs a signed RECOVERY; at most one torn record is discarded | Restart the agent with the same arguments |
| Evidence missing for a seat | Seat shows no log, or a receipt names events the log lacks | Look for the persistent volume; do not "fix" files |
| A lab assistant deleted files | Chain break, missing range or truncation finding, plus the witness copy | Preserve both copies; run verify on each |

## 7. Privacy

Candidates are pseudonymous in the roster. File names are recorded, contents only at
submission. Keep the roster-to-name mapping outside this system. How India's DPDP Act
applies has not been reviewed.
