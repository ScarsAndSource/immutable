# Limitations

Said plainly, because the project's value is its honesty.

## What a verdict means

- **Tamper-evident, not tamper-proof.** A person with administrator rights on a workstation
  can read its signing key. We bound that, we do not prevent it (threat T4, T14).
- **A verdict is not a finding of guilt.** `TAMPER_SUSPECTED` means the evidence is
  inconsistent and a human must look. Honest faults produce notes, not suspicion (T11).
- **Time is a claim.** Wall-clock times come from the workstation. Only an outside holder's
  clock bounds them, and only from above.

## What is out of scope

- Remote-solver cheating, someone else typing, hardware keyloggers.
- Assessor key compromise, or a roster swapped before the exam (T19).
- Collusion between a student and the witness operator (T23).
- Legal admissibility of any output. No legal review has happened.
- Any form of surveillance. This is a feature: see `docs/POLICY.md`.

## What the prototype is

- A **simulated lab**. The crypto, WAL recovery, witness, verifier and tamper lab are real
  code. No real institute has piloted it.
- All false-alarm numbers are measured on simulated sessions and must be labelled so.
- The tamper lab has 37 scripted scenarios; passing them shows the verifier handles those
  attacks, not that no other attack exists.
- The **web console is a one-process demonstrator**. A real lab runs the agent per
  workstation, the witness on another machine, and the assessor tools offline.
- Power-loss testing uses a fault-injection file layer plus one real VM power-off. Whether
  `fsync` is honest on a given disk or hypervisor is something to measure there, not assume.
- The sandboxed runner is a leash, not a cage. It stops runaway loops, memory and output; it
  does not stop code from touching the student's own machine.

## Known gaps

- The standalone receipt validator checks seats on the roster only. Seats created by a
  transfer are checked through the full evidence path.
- A receipt forged by a user with root is caught only if an outside holder or the assessor's
  own copy disagrees. That is why A2 needs both a receipt and an outside anchor.
- Restore-on-reboot lab software wipes local state. It needs a persistent evidence volume,
  and without one the seat shows up as a missing log (T13).
- Not built: Raspberry Pi witness, offline browser receipt validator, chained signed ingest log.
- Windows is best-effort; resource limits in the runner are POSIX only.
- Hindi student strings need native review.
- Teacher board: liveness indicates machine/network state, not proctoring or student behavior surveillance (by design; see docs/TEACHER_BOARD.md).
