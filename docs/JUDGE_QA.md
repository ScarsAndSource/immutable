# Hard questions, short honest answers

Read figures from `docs/EVALUATION.md` results, never from memory.

1. **A student with root can forge the whole history.** Yes, if no outside party ever saw a
   head (T4). We bound it: the witness holds heads during the exam, so a forged history must
   contradict what the witness holds. With no anchor the verifier prints NO_ANCHOR and never a
   green tick. We do not claim to prevent it.

2. **Why not a blockchain?** There is no trust problem between many equal parties and no
   internet to rely on. One witness on the LAN plus the assessor's pinned key gives the
   property needed: someone other than the student held the head. A chain adds cost and a
   network dependency for no extra guarantee here.

3. **Isn't this just a hash chain?** A bare chain proves nothing about completeness: the tail
   can be cut and re-chained. What is new is the system around it: pinned roster identity,
   witness cosigning with refusal on disagreement, signed recovery after power loss,
   deterministic reconciliation, a receipt anyone can check offline, and a verifier that
   reports what cannot be proven.

4. **Is the false-alarm number credible?** It is simulated and labelled so. It reports an
   upper bound (rule of three) over a stated number of clean sessions, with notes counted
   separately from suspicion. Real-lab data is the missing piece and we say so.

5. **What if the witness fails or lies?** Down: the gap shows as unanchored tail and nothing
   is lost; the courier retries. Fed two histories: it keeps one hash per (session, seat, seq)
   and refuses the batch (T20). Colluding with a student: out of scope, stated (T23).

6. **Remote-desktop or outside-help cheating?** Out of scope, stated. This shows what the
   machine logged, not who was at it.

7. **Clock changes across a reboot?** Inside one boot, wall time must agree with boot time.
   Across reboots we report time as uncertain, bounded above by an outside holder's clock. We
   never alarm on absolute wall time, because lab clocks are often wrong.

8. **Truncation disguised as a power cut?** Power loss may tear only the final record, and
   recovery must emit a signed RECOVERY event with the hash of what was discarded. Anything
   beyond one torn record is a finding. A witness-held head beyond the cut conflicts too.

9. **Surveillance and privacy law?** The event allow-list is code: no keystrokes, screens,
   cameras or biometrics can be carried. Candidates are pseudonymous. Legal review, including
   India's DPDP Act, has not happened and we say so.

10. **Labs that restore themselves on reboot?** That wipes local state. Deployment requires a
    persistent evidence volume; without it the seat shows as a missing log (T13). We document
    it and detect it; we cannot fix a lab image.
