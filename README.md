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

    pip install -e .
    python tools/gen_vectors.py
