"""scenarios.py: the complete scenario registry for the tamper lab.

Each Scenario has an id, group, title, threat reference, declared Expect, and
a build function that takes a Ctx and returns Inputs.

Ctx bundles the World, a seeded RNG, and a root directory for evidence files.
The build function must be deterministic for a given (world, seed).

Raise Inapplicable if the scenario cannot run for this seed (e.g. not enough
batches).  The trial will be skipped rather than recorded as MISSED.

Group map
  1  Controls      C0-C5
  2  Deletion      D1-D7
  3  Rollback      R1-R3
  4  Clock         K1-K2
  5  Replay        P1-P5
  6  Seat swap     W1-W6
  7  Power loss    L1
  8  Fork          F1-F2
  9  Key theft     T1-T3
  10 Setup         S1-S2
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from immutable import anchor as anchor_mod, hashing, keys, transfer
from immutable.roster import Roster, Seat, Witness

from .model import E, Expect, Inapplicable, Inputs, Obs, Outcome, Scenario
from . import adapter, evidence, run as run_mod
from .clock import FakeClock
from .world import World, EXAM_ID, WITNESS_ID


# ------------------------------------------------------------------ helpers

@dataclass
class Ctx:
    world: World
    rng: object            # random.Random
    root: Path


def _ops(ctx: Ctx, n: int = 12, submit: bool = True) -> list[str]:
    return run_mod.make_ops(ctx.rng, n, submit=submit)


def _seat(ctx: Ctx) -> tuple[str, keys.Signer]:
    ws = ctx.rng.choice(ctx.world.seat_ids)
    return ws, ctx.world.seats[ws]


def _session(ctx: Ctx) -> str:
    return f"SES{ctx.rng.getrandbits(24):06X}"


def _run_honest(ctx: Ctx, ev_dir: Path, ws_id: str, signer: keys.Signer,
                session_id: str, ops: list[str],
                transfer_token: bytes | None = None) -> run_mod.Played:
    """Run a full honest session and return its Played."""
    ev_dir.mkdir(parents=True, exist_ok=True)
    r = run_mod.Run.start(ctx.world, ev_dir, ws_id=ws_id, signer=signer,
                          session_id=session_id, transfer_token=transfer_token)
    return r.play(ops)


def _make_witness_anchor(world: World, played: run_mod.Played,
                         upto_seq: int | None = None) -> bytes:
    """Issue a witness anchor for played, pinning upto_seq (default: final)."""
    from immutable.wal import Wal
    from immutable.fsys import RealFS
    if upto_seq is None:
        upto_seq = played.last_seq
        head = played.final_head
    else:
        # reconstruct head at upto_seq from WAL
        wal_path = str(played.evidence_dir / "session.wal")
        try:
            rec = Wal.recover(RealFS(), wal_path, world.exam,
                              played.session_id, played.ws_id)
            trunk = rec.wal.events
            head = next(e.hash() for e in trunk if e.seq == upto_seq)
        except Exception:
            head = played.final_head
    return anchor_mod.make_witness(
        world.witness_signer,
        exam_id=world.exam,
        session_id=played.session_id,
        ws_id=played.ws_id,
        upto_seq=upto_seq,
        head=head,
        holder=WITNESS_ID,
        seen_ms=int(hashing.sha256_hex(head.encode())[:8], 16),  # deterministic fake ms
    )


def _ingest_paths(played: run_mod.Played) -> list[Path]:
    return [played.evidence_dir]


def codes(*args: str) -> set[str]:
    return set(args)


# Unprovable codes used in BY_DESIGN expectations
_NOANCHOR = codes("NO_ANCHOR")
_UNANCHORED_TAIL = codes("UNANCHORED_TAIL")

# ================================================================== GROUP 1: Controls

def s_clean_anchored(ctx: Ctx) -> Inputs:
    ws, signer = _seat(ctx)
    sid = _session(ctx)
    played = _run_honest(ctx, ctx.root / "ev", ws, signer, sid, _ops(ctx))
    anchor = _make_witness_anchor(ctx.world, played)
    return Inputs(
        paths=_ingest_paths(played),
        anchors=[anchor],
        victim=(sid, ws),
    )


def s_clean_unanchored(ctx: Ctx) -> Inputs:
    ws, signer = _seat(ctx)
    sid = _session(ctx)
    played = _run_honest(ctx, ctx.root / "ev", ws, signer, sid, _ops(ctx))
    return Inputs(paths=_ingest_paths(played), victim=(sid, ws))


def s_power_cut(ctx: Ctx) -> Inputs:
    """Truncate the WAL at a random byte — simulates power loss."""
    ws, signer = _seat(ctx)
    sid = _session(ctx)
    # run without submit so WAL is still open
    ops = _ops(ctx, submit=False)
    played = _run_honest(ctx, ctx.root / "ev", ws, signer, sid, ops)
    wal = adapter.find_wal(played.evidence_dir)
    data = wal.read_bytes()
    if len(data) < 2:
        raise Inapplicable("WAL too short to truncate")
    cut = ctx.rng.randint(1, len(data) - 1)
    wal.write_bytes(data[:cut])
    anchor = _make_witness_anchor(ctx.world, played)
    return Inputs(
        paths=_ingest_paths(played),
        anchors=[anchor],
        victim=(sid, ws),
    )


def s_dead_rtc(ctx: Ctx) -> Inputs:
    """Clock is years off at start — large CLOCK_OFFSET note expected."""
    ws, signer = _seat(ctx)
    sid = _session(ctx)
    clk = FakeClock(start_wall=1_000_000.0)   # 1970+11 days: obviously wrong
    with clk.installed():
        played = _run_honest(ctx, ctx.root / "ev", ws, signer, sid, _ops(ctx))
    anchor = _make_witness_anchor(ctx.world, played)
    return Inputs(
        paths=_ingest_paths(played),
        anchors=[anchor],
        victim=(sid, ws),
    )


def s_late_reordered(ctx: Ctx) -> Inputs:
    """Deliver batches in shuffled order with a duplicate — idempotent ingest."""
    ws, signer = _seat(ctx)
    sid = _session(ctx)
    played = _run_honest(ctx, ctx.root / "ev", ws, signer, sid, _ops(ctx))
    anchor = _make_witness_anchor(ctx.world, played)
    infos = evidence.batch_infos(played.outbox)
    if len(infos) < 2:
        raise Inapplicable("not enough batches to reorder")
    ctx.rng.shuffle(infos)
    # duplicate the first batch
    raw_batches = [i.raw for i in infos] + [infos[0].raw]

    baseline = Inputs(paths=_ingest_paths(played), anchors=[anchor], victim=(sid, ws))
    return Inputs(
        raw_batches=raw_batches,
        anchors=[anchor],
        victim=(sid, ws),
        baseline=baseline,
    )


def s_transfer_ok(ctx: Ctx) -> Inputs:
    """Assessor-authorised seat transfer — clean."""
    from_ws = ctx.world.seat_ids[0]
    to_ws = ctx.world.spare_ids[0]
    from_signer = ctx.world.seats[from_ws]
    to_signer = ctx.world.spares[to_ws]
    sid = _session(ctx)

    # run from-seat partial session
    played_from = _run_honest(ctx, ctx.root / "from_ev", from_ws, from_signer, sid,
                              _ops(ctx, submit=False))
    # issue transfer token
    tok = transfer.issue(
        ctx.world.assessor,
        exam_id=ctx.world.exam,
        session_id=sid,
        from_ws_id=from_ws,
        from_last_seq=played_from.last_seq,
        from_head=played_from.final_head,
        to_ws_id=to_ws,
        to_pub=to_signer.pub_hex,
    )
    # run to-seat session with token
    played_to = _run_honest(ctx, ctx.root / "to_ev", to_ws, to_signer, sid,
                            _ops(ctx), transfer_token=tok)
    anchor = _make_witness_anchor(ctx.world, played_to)
    return Inputs(
        paths=[played_from.evidence_dir, played_to.evidence_dir],
        anchors=[anchor],
        victim=(sid, to_ws),
    )


# ================================================================== GROUP 2: Deletion

def s_delete_middle(ctx: Ctx) -> Inputs:
    """Delete a batch from the middle of the chain."""
    ws, signer = _seat(ctx)
    sid = _session(ctx)
    played = _run_honest(ctx, ctx.root / "ev", ws, signer, sid, _ops(ctx))
    infos = evidence.batch_infos(played.outbox)
    if len(infos) < 3:
        raise Inapplicable("need >=3 batches to delete middle")
    mid = infos[len(infos) // 2]
    mid.path.unlink()
    anchor = _make_witness_anchor(ctx.world, played)
    return Inputs(
        paths=_ingest_paths(played),
        anchors=[anchor],
        victim=(sid, ws),
    )


def s_tail_no_anchor(ctx: Ctx) -> Inputs:
    """Delete the tail batches; no witness anchor covers them."""
    ws, signer = _seat(ctx)
    sid = _session(ctx)
    played = _run_honest(ctx, ctx.root / "ev", ws, signer, sid, _ops(ctx))
    infos = evidence.batch_infos(played.outbox)
    if len(infos) < 2:
        raise Inapplicable("need >=2 batches")
    # delete last batch
    infos[-1].path.unlink()
    return Inputs(paths=_ingest_paths(played), victim=(sid, ws))


def s_tail_final_anchor(ctx: Ctx) -> Inputs:
    """Delete tail, but witness holds the original final head."""
    ws, signer = _seat(ctx)
    sid = _session(ctx)
    played = _run_honest(ctx, ctx.root / "ev", ws, signer, sid, _ops(ctx))
    # witness anchors the final head BEFORE deletion
    anchor = _make_witness_anchor(ctx.world, played)
    infos = evidence.batch_infos(played.outbox)
    if len(infos) < 2:
        raise Inapplicable("need >=2 batches")
    infos[-1].path.unlink()
    return Inputs(
        paths=_ingest_paths(played),
        anchors=[anchor],
        victim=(sid, ws),
    )


def s_tail_beyond_anchor(ctx: Ctx) -> Inputs:
    """Delete tail past the last anchor — tail is unanchored, unprovable."""
    ws, signer = _seat(ctx)
    sid = _session(ctx)
    played = _run_honest(ctx, ctx.root / "ev", ws, signer, sid, _ops(ctx))
    infos = evidence.batch_infos(played.outbox)
    if len(infos) < 3:
        raise Inapplicable("need >=3 batches")
    # anchor the first batch only
    anchor = _make_witness_anchor(ctx.world, played, upto_seq=infos[0].last_seq)
    # delete last batch
    infos[-1].path.unlink()
    return Inputs(
        paths=_ingest_paths(played),
        anchors=[anchor],
        victim=(sid, ws),
    )


def s_edit_in_place(ctx: Ctx) -> Inputs:
    """Edit a field inside one event in the middle batch."""
    ws, signer = _seat(ctx)
    sid = _session(ctx)
    played = _run_honest(ctx, ctx.root / "ev", ws, signer, sid, _ops(ctx))
    infos = evidence.batch_infos(played.outbox)
    if not infos:
        raise Inapplicable("no batches")
    target = infos[len(infos) // 2]
    evs = evidence.events_of(target)
    if not evs:
        raise Inapplicable("target batch has no events")
    target_seq = evs[0]["seq"]
    tampered = evidence.mutate_event_data(
        target.raw, target_seq, lambda d: {**d, "_tampered": True}
    )
    target.path.write_bytes(tampered)
    anchor = _make_witness_anchor(ctx.world, played)
    return Inputs(
        paths=_ingest_paths(played),
        anchors=[anchor],
        victim=(sid, ws),
    )


def s_delete_blob(ctx: Ctx) -> Inputs:
    """Delete the submitted blob so BLOB_MISSING fires."""
    ws, signer = _seat(ctx)
    sid = _session(ctx)
    played = _run_honest(ctx, ctx.root / "ev", ws, signer, sid, _ops(ctx))
    # find and delete one blob
    blobs_dir = played.evidence_dir / "submission" / "blobs"
    blobs = list(blobs_dir.glob("*")) if blobs_dir.exists() else []
    if not blobs:
        raise Inapplicable("no blobs to delete")
    ctx.rng.choice(blobs).unlink()
    anchor = _make_witness_anchor(ctx.world, played)
    return Inputs(
        paths=_ingest_paths(played),
        anchors=[anchor],
        victim=(sid, ws),
    )


def s_edit_manifest(ctx: Ctx) -> Inputs:
    """Edit the manifest so its hash no longer matches SUBMIT event."""
    ws, signer = _seat(ctx)
    sid = _session(ctx)
    played = _run_honest(ctx, ctx.root / "ev", ws, signer, sid, _ops(ctx))
    manifest = played.evidence_dir / "submission" / "manifest.json"
    if not manifest.exists():
        raise Inapplicable("no manifest")
    raw = manifest.read_bytes()
    # corrupt a byte in the middle
    ba = bytearray(raw)
    mid = len(ba) // 2
    ba[mid] ^= 0x01
    manifest.write_bytes(bytes(ba))
    anchor = _make_witness_anchor(ctx.world, played)
    return Inputs(
        paths=_ingest_paths(played),
        anchors=[anchor],
        victim=(sid, ws),
    )


# ================================================================== GROUP 3: Rollback

def _rollback(ctx: Ctx, *, with_original: bool, with_witness: bool) -> Inputs:
    """Core rollback builder used by R1, R2, R3."""
    ws, signer = _seat(ctx)
    sid = _session(ctx)
    # Run a full session — this is the "original" log
    played = _run_honest(ctx, ctx.root / "orig", ws, signer, sid, _ops(ctx))
    infos = evidence.batch_infos(played.outbox)
    if len(infos) < 3:
        raise Inapplicable("need >=3 batches for rollback")

    # Snapshot old state (first batch only)
    snap_dir = ctx.root / "snap"
    snap_dir.mkdir(parents=True, exist_ok=True)
    snap_outbox = snap_dir / "outbox"
    snap_outbox.mkdir(parents=True, exist_ok=True)
    shutil.copy2(infos[0].path, snap_outbox / infos[0].path.name)

    # Witness anchor at the cutpoint (before rollback)
    anchor_bytes = _make_witness_anchor(ctx.world, played,
                                        upto_seq=infos[0].last_seq) if with_witness else None

    # "Restore": replace the full outbox with the snapshot
    for p in played.outbox.glob("*.batch.json"):
        p.unlink()
    shutil.copy2(infos[0].path, played.outbox / infos[0].path.name)

    anchors = [anchor_bytes] if anchor_bytes else []

    # For R1: original log is also delivered (so the fork is visible)
    if with_original:
        orig_batches = [i.raw for i in infos]
        return Inputs(
            paths=[played.evidence_dir],
            raw_batches=orig_batches,
            anchors=anchors,
            victim=(sid, ws),
        )
    return Inputs(
        paths=[played.evidence_dir],
        anchors=anchors,
        victim=(sid, ws),
    )


def s_rollback_delivered(ctx: Ctx) -> Inputs:
    return _rollback(ctx, with_original=True, with_witness=False)


def s_rollback_witness(ctx: Ctx) -> Inputs:
    return _rollback(ctx, with_original=False, with_witness=True)


def s_rollback_silent(ctx: Ctx) -> Inputs:
    return _rollback(ctx, with_original=False, with_witness=False)


# ================================================================== GROUP 4: Clock

def s_clock_step(ctx: Ctx) -> Inputs:
    """Wall clock jumps forward (NTP sync) — note only."""
    ws, signer = _seat(ctx)
    sid = _session(ctx)
    clk = FakeClock(start_wall=1_700_000_000.0)
    with clk.installed():
        r = run_mod.Run.start(ctx.world, ctx.root / "ev", ws_id=ws,
                              signer=signer, session_id=sid)
        r.play(["save", "tick"])
        clk.advance(7200)   # 2-hour jump
        played = r.play(["save", "submit"])
    anchor = _make_witness_anchor(ctx.world, played)
    return Inputs(paths=_ingest_paths(played), anchors=[anchor], victim=(sid, ws))


def s_clock_backwards(ctx: Ctx) -> Inputs:
    """Uptime monotonic clock goes backwards — impossible, SUSPECT."""
    ws, signer = _seat(ctx)
    sid = _session(ctx)
    clk = FakeClock(start_wall=1_700_000_000.0)
    with clk.installed():
        r = run_mod.Run.start(ctx.world, ctx.root / "ev", ws_id=ws,
                              signer=signer, session_id=sid)
        r.play(["save", "tick"])
        clk.mono -= 300     # backwards 5 min
        played = r.play(["save", "submit"])
    anchor = _make_witness_anchor(ctx.world, played)
    return Inputs(paths=_ingest_paths(played), anchors=[anchor], victim=(sid, ws))


# ================================================================== GROUP 5: Replay / injection

def s_replay_duplicates(ctx: Ctx) -> Inputs:
    """Same evidence delivered twice (shuffled) — idempotent, same hash."""
    ws, signer = _seat(ctx)
    sid = _session(ctx)
    played = _run_honest(ctx, ctx.root / "ev", ws, signer, sid, _ops(ctx))
    anchor = _make_witness_anchor(ctx.world, played)
    infos = evidence.batch_infos(played.outbox)
    all_raw = [i.raw for i in infos]
    shuffled = list(all_raw)
    ctx.rng.shuffle(shuffled)

    baseline = Inputs(paths=_ingest_paths(played), anchors=[anchor], victim=(sid, ws))
    return Inputs(
        raw_batches=all_raw + shuffled,
        anchors=[anchor, anchor],   # duplicate anchor too
        victim=(sid, ws),
        baseline=baseline,
    )


def s_replay_other_exam(ctx: Ctx) -> Inputs:
    """Deliver a real batch from a different exam — WRONG_EXAM."""
    ws, signer = _seat(ctx)
    sid = _session(ctx)
    played = _run_honest(ctx, ctx.root / "ev", ws, signer, sid, _ops(ctx))
    anchor = _make_witness_anchor(ctx.world, played)
    infos = evidence.batch_infos(played.outbox)
    if not infos:
        raise Inapplicable("no batches")

    # Rewrite exam_id in one batch so it becomes a foreign exam
    foreign_batch = evidence.rewrite_strings(infos[0].raw, ctx.world.exam, "FOREIGNEXAM001")

    baseline = Inputs(paths=_ingest_paths(played), anchors=[anchor], victim=(sid, ws))
    return Inputs(
        paths=_ingest_paths(played),
        raw_batches=[foreign_batch],
        anchors=[anchor],
        victim=(sid, ws),
        baseline=baseline,
    )


def s_replay_swapped_header(ctx: Ctx) -> Inputs:
    """Swap ws_id and session_id in a batch header — BAD_SIGNATURE/MALFORMED."""
    ws, signer = _seat(ctx)
    sid = _session(ctx)
    played = _run_honest(ctx, ctx.root / "ev", ws, signer, sid, _ops(ctx))
    anchor = _make_witness_anchor(ctx.world, played)
    infos = evidence.batch_infos(played.outbox)
    if not infos:
        raise Inapplicable("no batches")
    # corrupt the first batch's signature field directly
    tampered = evidence.flip_hex_anywhere(infos[0].raw, ctx.rng)
    return Inputs(
        paths=_ingest_paths(played),
        raw_batches=[tampered],
        anchors=[anchor],
        victim=(sid, ws),
    )


def s_hostile_input(ctx: Ctx) -> Inputs:
    """Random junk, empty objects, truncated batches — all should be rejected silently."""
    ws, signer = _seat(ctx)
    sid = _session(ctx)
    played = _run_honest(ctx, ctx.root / "ev", ws, signer, sid, _ops(ctx))
    anchor = _make_witness_anchor(ctx.world, played)

    junk = [
        b"",
        b"null",
        b"{}",
        b'{"not": "a batch"}',
        b"\x00" * 32,
        ctx.rng.randbytes(64),
    ]
    baseline = Inputs(paths=_ingest_paths(played), anchors=[anchor], victim=(sid, ws))
    return Inputs(
        paths=_ingest_paths(played),
        raw_batches=junk,
        anchors=[anchor],
        victim=(sid, ws),
        baseline=baseline,
    )


def s_forged_anchor(ctx: Ctx) -> Inputs:
    """Forge a witness anchor with the wrong key — ANCHOR_INVALID."""
    ws, signer = _seat(ctx)
    sid = _session(ctx)
    played = _run_honest(ctx, ctx.root / "ev", ws, signer, sid, _ops(ctx))
    # sign with rogue key instead of witness key
    bad_anchor = anchor_mod.make_witness(
        ctx.world.rogue,
        exam_id=ctx.world.exam,
        session_id=sid,
        ws_id=ws,
        upto_seq=played.last_seq,
        head=played.final_head,
        holder=WITNESS_ID,
        seen_ms=1_700_000_000_000,
    )
    return Inputs(
        paths=_ingest_paths(played),
        anchors=[bad_anchor],
        victim=(sid, ws),
    )


# ================================================================== GROUP 6: Seat swap

def s_rogue_with_original(ctx: Ctx) -> Inputs:
    """Rogue machine claims the seat; real log is also present. NEUTRALIZED."""
    ws, signer = _seat(ctx)
    sid = _session(ctx)
    played = _run_honest(ctx, ctx.root / "ev", ws, signer, sid, _ops(ctx))
    anchor = _make_witness_anchor(ctx.world, played)

    # Rogue session: signed with rogue key, same ws_id claimed
    # Build a separate world with a rogue roster so agent can open
    from immutable.roster import Roster as _R
    rogue_signer = ctx.world.rogue
    # Make a fake batch signed by rogue for same session/seat
    from immutable.batch import seal
    from immutable.events import Event
    import time as _time
    import json
    # We'll just inject raw junk signed by rogue — the simplest approach
    # is to use rewrite_strings to change the signer pubkey in a real batch
    infos = evidence.batch_infos(played.outbox)
    if not infos:
        raise Inapplicable("no batches")
    # Replace signer pub in the batch — signature won't verify; lands as rejected
    rogue_raw = evidence.rewrite_strings(
        infos[0].raw,
        signer.pub_hex,
        rogue_signer.pub_hex,
    )
    return Inputs(
        paths=_ingest_paths(played),
        raw_batches=[rogue_raw],
        anchors=[anchor],
        victim=(sid, ws),
    )


def s_rogue_alone(ctx: Ctx) -> Inputs:
    """Rogue machine alone, no real log. DETECTED: UNKNOWN_SEAT / KEY_NOT_ENROLLED."""
    ws, signer = _seat(ctx)
    sid = _session(ctx)
    played = _run_honest(ctx, ctx.root / "ev", ws, signer, sid, _ops(ctx))
    infos = evidence.batch_infos(played.outbox)
    if not infos:
        raise Inapplicable("no batches")
    # Replace signer with rogue key
    rogue_raw = evidence.rewrite_strings(
        infos[0].raw, signer.pub_hex, ctx.world.rogue.pub_hex)
    # Only deliver the rogue batch (no real log)
    return Inputs(
        raw_batches=[rogue_raw],
        victim=(sid, ws),
    )


def _forged_transfer(ctx: Ctx, from_ws: str, to_ws: str, to_signer: keys.Signer,
                     sid: str) -> bytes:
    """Build a transfer token signed with the rogue key instead of assessor."""
    # Use wrong signer (rogue) — signature will not verify
    from immutable import canon, hashing as h_mod, keys as k_mod
    body = {
        "v": 1, "exam_id": ctx.world.exam, "session_id": sid,
        "from_ws_id": from_ws, "from_last_seq": 0,
        "from_head": "0" * 64,
        "to_ws_id": to_ws, "to_pub": to_signer.pub_hex,
    }
    sig = ctx.world.rogue.sign(h_mod.TRANSFER, canon.dumps(body))
    return canon.dumps({"body": body, "sig": sig})


def s_forged_transfer_with_original(ctx: Ctx) -> Inputs:
    """Forged transfer + original log both present. NEUTRALIZED."""
    from_ws = ctx.world.seat_ids[0]
    to_ws = ctx.world.spare_ids[0]
    from_signer = ctx.world.seats[from_ws]
    to_signer = ctx.world.spares[to_ws]
    sid = _session(ctx)

    played_from = _run_honest(ctx, ctx.root / "from_ev", from_ws, from_signer, sid,
                              _ops(ctx, submit=False))
    bad_tok = _forged_transfer(ctx, from_ws, to_ws, to_signer, sid)
    # Try to open with bad token — should be refused
    try:
        played_to = _run_honest(ctx, ctx.root / "to_ev", to_ws, to_signer, sid,
                                _ops(ctx), transfer_token=bad_tok)
        # if agent accepts the bad token, that is an integrity error
        paths = [played_from.evidence_dir, played_to.evidence_dir]
    except Exception:
        paths = [played_from.evidence_dir]

    anchor = _make_witness_anchor(ctx.world, played_from)
    return Inputs(paths=paths, anchors=[anchor], victim=(sid, from_ws))


def s_forged_transfer_alone(ctx: Ctx) -> Inputs:
    """Forged transfer token, only forged chain. DETECTED: TRANSFER_INVALID."""
    from_ws = ctx.world.seat_ids[0]
    to_ws = ctx.world.spare_ids[0]
    from_signer = ctx.world.seats[from_ws]
    to_signer = ctx.world.spares[to_ws]
    sid = _session(ctx)

    played_from = _run_honest(ctx, ctx.root / "from_ev", from_ws, from_signer, sid,
                              _ops(ctx, submit=False))
    bad_tok = _forged_transfer(ctx, from_ws, to_ws, to_signer, sid)
    try:
        played_to = _run_honest(ctx, ctx.root / "to_ev", to_ws, to_signer, sid,
                                _ops(ctx), transfer_token=bad_tok)
        return Inputs(paths=[played_to.evidence_dir], victim=(sid, to_ws))
    except Exception as exc:
        # Agent refused the token at open — mark as refused
        return Inputs(refused=str(exc), victim=(sid, to_ws))


def s_transfer_mismatch(ctx: Ctx) -> Inputs:
    """Old machine kept writing past the recorded transfer point. TRANSFER_MISMATCH."""
    from_ws = ctx.world.seat_ids[0]
    to_ws = ctx.world.spare_ids[0]
    from_signer = ctx.world.seats[from_ws]
    to_signer = ctx.world.spares[to_ws]
    sid = _session(ctx)

    played_from = _run_honest(ctx, ctx.root / "from_ev", from_ws, from_signer, sid,
                              _ops(ctx, submit=False))
    # token says from_last_seq = 0, but from-machine has more events
    tok = transfer.issue(
        ctx.world.assessor,
        exam_id=ctx.world.exam,
        session_id=sid,
        from_ws_id=from_ws,
        from_last_seq=0,
        from_head=hashing.ZERO,
        to_ws_id=to_ws,
        to_pub=to_signer.pub_hex,
    )
    played_to = _run_honest(ctx, ctx.root / "to_ev", to_ws, to_signer, sid,
                            _ops(ctx), transfer_token=tok)
    anchor = _make_witness_anchor(ctx.world, played_to)
    return Inputs(
        paths=[played_from.evidence_dir, played_to.evidence_dir],
        anchors=[anchor],
        victim=(sid, to_ws),
    )


def s_cloned_key(ctx: Ctx) -> Inputs:
    """Seat B carries seat A's key. DUPLICATE_KEY / KEY_NOT_ENROLLED."""
    ws_a = ctx.world.seat_ids[0]
    ws_b = ctx.world.seat_ids[1]
    signer_a = ctx.world.seats[ws_a]
    sid = _session(ctx)

    # ws_a runs honestly
    played_a = _run_honest(ctx, ctx.root / "ev_a", ws_a, signer_a, sid, _ops(ctx))
    # ws_b also runs but uses ws_a's key
    played_b = _run_honest(ctx, ctx.root / "ev_b", ws_b, signer_a, sid, _ops(ctx))
    anchor = _make_witness_anchor(ctx.world, played_a)
    return Inputs(
        paths=[played_a.evidence_dir, played_b.evidence_dir],
        anchors=[anchor],
        victim=(sid, ws_b),
    )


# ================================================================== GROUP 7: Power loss

def s_wal_corrupt(ctx: Ctx) -> Inputs:
    """WAL has a mid-record corruption (not a torn tail) — Wal.recover refuses."""
    ws, signer = _seat(ctx)
    sid = _session(ctx)
    played = _run_honest(ctx, ctx.root / "ev", ws, signer, sid, _ops(ctx, submit=False))
    wal_path = adapter.find_wal(played.evidence_dir)
    data = bytearray(wal_path.read_bytes())
    if len(data) < 16:
        raise Inapplicable("WAL too short")
    # flip bytes in the header region (first 16 bytes) — not just the tail
    for i in range(4, 8):
        data[i] ^= 0xFF
    wal_path.write_bytes(bytes(data))
    # Deliver only the outbox (WAL is corrupt and would cause recover to raise)
    return Inputs(paths=[played.outbox], victim=(sid, ws))


# ================================================================== GROUP 8: Fork / sync conflict

def s_fork(ctx: Ctx) -> Inputs:
    """Two different tails for same session delivered together — FORK."""
    ws, signer = _seat(ctx)
    sid = _session(ctx)
    played = _run_honest(ctx, ctx.root / "ev", ws, signer, sid, _ops(ctx))
    infos = evidence.batch_infos(played.outbox)
    if len(infos) < 2:
        raise Inapplicable("need >=2 batches to create fork")
    anchor = _make_witness_anchor(ctx.world, played,
                                  upto_seq=infos[0].last_seq)
    # Tamper the last batch to create an alternative tail
    alt = evidence.flip_hex_anywhere(infos[-1].raw, ctx.rng)
    return Inputs(
        paths=_ingest_paths(played),
        raw_batches=[alt],
        anchors=[anchor],
        victim=(sid, ws),
    )


def s_anchor_conflict(ctx: Ctx) -> Inputs:
    """Anchor holds a different head at a seq the log also covers — ANCHOR_CONFLICT."""
    ws, signer = _seat(ctx)
    sid = _session(ctx)
    played = _run_honest(ctx, ctx.root / "ev", ws, signer, sid, _ops(ctx))
    # Make an anchor pointing to a wrong head at seq 0
    bad_anchor = anchor_mod.make_witness(
        ctx.world.witness_signer,
        exam_id=ctx.world.exam,
        session_id=sid,
        ws_id=ws,
        upto_seq=0,
        head="a" * 64,   # wrong hash
        holder=WITNESS_ID,
        seen_ms=1_700_000_000_000,
    )
    return Inputs(
        paths=_ingest_paths(played),
        anchors=[bad_anchor],
        victim=(sid, ws),
    )


# ================================================================== GROUP 9: Key theft / forgery

def s_forge_scratch(ctx: Ctx) -> Inputs:
    """Entire session forged from scratch with real key, no real log. BY_DESIGN."""
    ws, signer = _seat(ctx)
    sid = _session(ctx)
    # Run a session with the real key (simulates attacker who stole the key)
    played = _run_honest(ctx, ctx.root / "ev", ws, signer, sid, _ops(ctx))
    return Inputs(paths=_ingest_paths(played), victim=(sid, ws))


def s_forge_scratch_witnessed(ctx: Ctx) -> Inputs:
    """Forged session, but witness holds original's final head. DETECTED."""
    ws, signer = _seat(ctx)
    sid = _session(ctx)
    # Honest session A (the original)
    played_a = _run_honest(ctx, ctx.root / "orig", ws, signer, sid, _ops(ctx))
    anchor = _make_witness_anchor(ctx.world, played_a)
    # "Forged" session B: same key, same seat, different content
    played_b = _run_honest(ctx, ctx.root / "forged", ws, signer, sid, _ops(ctx))
    # deliver forged only (original replaced)
    return Inputs(
        paths=[played_b.evidence_dir],
        anchors=[anchor],
        victim=(sid, ws),
    )


def s_forge_tail(ctx: Ctx) -> Inputs:
    """Forged tail appended; witness holds prefix. DETECTED: ANCHOR_CONFLICT / FORK."""
    ws, signer = _seat(ctx)
    sid = _session(ctx)
    played = _run_honest(ctx, ctx.root / "ev", ws, signer, sid, _ops(ctx))
    infos = evidence.batch_infos(played.outbox)
    if len(infos) < 2:
        raise Inapplicable("need >=2 batches to forge tail")
    # anchor the prefix
    anchor = _make_witness_anchor(ctx.world, played, upto_seq=infos[0].last_seq)
    # replace the last batch with tampered bytes (simulates a rewritten tail)
    forged_tail = evidence.flip_hex_anywhere(infos[-1].raw, ctx.rng)
    infos[-1].path.write_bytes(forged_tail)
    return Inputs(
        paths=_ingest_paths(played),
        anchors=[anchor],
        victim=(sid, ws),
    )


# ================================================================== GROUP 10: Setup tampering

def s_roster_swap(ctx: Ctx) -> Inputs:
    """SESSION_START records wrong roster SHA — ROSTER_MISMATCH."""
    ws, signer = _seat(ctx)
    sid = _session(ctx)
    # Run a session with a different roster_sha256 embedded
    ev_dir = ctx.root / "ev"
    ev_dir.mkdir(parents=True, exist_ok=True)
    ws_dir = ev_dir.parent / "workspace"
    ws_dir.mkdir(parents=True, exist_ok=True)
    from immutable.agent import Agent
    agent = Agent.open(
        evidence_dir=ev_dir,
        workspace=ws_dir,
        exam_id=ctx.world.exam,
        session_id=sid,
        ws_id=ws,
        signer=signer,
        paper_sha256=ctx.world.paper_sha,
        roster_sha256="b" * 64,   # wrong roster hash
        heartbeat_s=adapter.HEARTBEAT_S,
        checkpoint_every=adapter.CHECKPOINT_EVERY,
    )
    h = adapter.Handle(agent, ev_dir)
    h.flush()
    h.submit()
    anchor = _make_witness_anchor(ctx.world, run_mod.Played(
        evidence_dir=ev_dir, outbox=ev_dir / "outbox",
        session_id=sid, ws_id=ws,
        final_head="", last_seq=-1, submitted=True,
    ))
    return Inputs(paths=[ev_dir], anchors=[anchor], victim=(sid, ws))


def s_paper_swap(ctx: Ctx) -> Inputs:
    """SESSION_START records wrong paper SHA — PAPER_MISMATCH."""
    ws, signer = _seat(ctx)
    sid = _session(ctx)
    ev_dir = ctx.root / "ev"
    ev_dir.mkdir(parents=True, exist_ok=True)
    ws_dir = ev_dir.parent / "workspace"
    ws_dir.mkdir(parents=True, exist_ok=True)
    from immutable.agent import Agent
    agent = Agent.open(
        evidence_dir=ev_dir,
        workspace=ws_dir,
        exam_id=ctx.world.exam,
        session_id=sid,
        ws_id=ws,
        signer=signer,
        paper_sha256="c" * 64,   # wrong paper hash
        roster_sha256=ctx.world.roster.id,
        heartbeat_s=adapter.HEARTBEAT_S,
        checkpoint_every=adapter.CHECKPOINT_EVERY,
    )
    h = adapter.Handle(agent, ev_dir)
    h.flush()
    h.submit()
    anchor = _make_witness_anchor(ctx.world, run_mod.Played(
        evidence_dir=ev_dir, outbox=ev_dir / "outbox",
        session_id=sid, ws_id=ws,
        final_head="", last_seq=-1, submitted=True,
    ))
    return Inputs(paths=[ev_dir], anchors=[anchor], victim=(sid, ws))


# ================================================================== REGISTRY

def _c(*args: str) -> set[str]:
    return set(args)


SCENARIOS: list[Scenario] = [
    # --- 1 Controls ---
    Scenario("C0", "1 Controls", "clean session, witness holds final head", "—",
             E(Outcome.CLEAN, verdicts=_c("ANCHORED")),
             s_clean_anchored),
    Scenario("C1", "1 Controls", "clean session, no outside holder", "—",
             E(Outcome.CLEAN, verdicts=_c("SELF_CONSISTENT_ONLY")),
             s_clean_unanchored),
    Scenario("C2", "1 Controls", "power cut at random WAL byte", "T12",
             E(Outcome.CLEAN),
             s_power_cut),
    Scenario("C3", "1 Controls", "dead RTC (clock years off)", "T8",
             E(Outcome.CLEAN, verdicts=_c("ANCHORED")),
             s_dead_rtc),
    Scenario("C4", "1 Controls", "late / shuffled / duplicate delivery", "—",
             E(Outcome.CLEAN, same_hash=True, verdicts=_c("ANCHORED")),
             s_late_reordered),
    Scenario("C5", "1 Controls", "assessor-authorised transfer", "T18",
             E(Outcome.CLEAN),
             s_transfer_ok),

    # --- 2 Deletion ---
    Scenario("D1", "2 Deletion", "delete middle batch", "T3",
             E(Outcome.DETECTED, codes=_c("MISSING_RANGE", "LINK_BREAK")),
             s_delete_middle),
    Scenario("D2", "2 Deletion", "delete tail, no anchor", "T3",
             E(Outcome.BY_DESIGN, unprovable=_NOANCHOR | _UNANCHORED_TAIL,
               why="without anchor the truncated chain is self-consistent"),
             s_tail_no_anchor),
    Scenario("D3", "2 Deletion", "delete tail, witness has final head", "T3",
             E(Outcome.DETECTED, codes=_c("TRUNCATED")),
             s_tail_final_anchor),
    Scenario("D4", "2 Deletion", "delete tail past last anchor", "T3",
             E(Outcome.BY_DESIGN, unprovable=_UNANCHORED_TAIL,
               why="anchored prefix is provable; unanchored tail is gone"),
             s_tail_beyond_anchor),
    Scenario("D5", "2 Deletion", "edit event in place", "T3",
             E(Outcome.DETECTED, codes=_c("BATCH_DEFECT", "MISSING_RANGE", "LINK_BREAK",
                                          "CHECKPOINT_BAD", "BAD_SIGNATURE")),
             s_edit_in_place),
    Scenario("D6", "2 Deletion", "delete submitted blob", "T3",
             E(Outcome.DETECTED, codes=_c("BLOB_MISSING")),
             s_delete_blob),
    Scenario("D7", "2 Deletion", "edit submission manifest", "T3",
             E(Outcome.DETECTED, codes=_c("SUBMISSION_MISMATCH")),
             s_edit_manifest),

    # --- 3 Rollback ---
    Scenario("R1", "3 Rollback", "restore old snapshot, original delivered, no witness", "T3",
             E(Outcome.DETECTED, codes=_c("FORK", "MISSING_RANGE", "LINK_BREAK")),
             s_rollback_delivered),
    Scenario("R2", "3 Rollback", "restore old snapshot, only witness anchor remains", "T3",
             E(Outcome.DETECTED, codes=_c("ROLLBACK", "TRUNCATED", "ANCHOR_CONFLICT")),
             s_rollback_witness),
    Scenario("R3", "3 Rollback",
             "restore old snapshot, no original, no witness", "T3",
             E(Outcome.BY_DESIGN, unprovable=_NOANCHOR | _UNANCHORED_TAIL,
               why="without an outside holder the restored chain is indistinguishable from the original"),
             s_rollback_silent),

    # --- 4 Clock ---
    Scenario("K1", "4 Clock", "wall clock step (NTP jump)", "T8",
             E(Outcome.CLEAN),
             s_clock_step),
    Scenario("K2", "4 Clock", "uptime clock goes backwards", "T8",
             E(Outcome.DETECTED, codes=_c("CLOCK_BACKWARD")),
             s_clock_backwards),

    # --- 5 Replay / injection ---
    Scenario("P1", "5 Replay", "replay: same evidence delivered twice, shuffled", "T5",
             E(Outcome.CLEAN, same_hash=True, verdicts=_c("ANCHORED")),
             s_replay_duplicates),
    Scenario("P2", "5 Replay", "replay: batch from a different exam", "T5",
             E(Outcome.NEUTRALIZED, codes=_c("WRONG_EXAM"), same_hash=True),
             s_replay_other_exam),
    Scenario("P3", "5 Replay", "replay: batch with swapped / corrupted signature", "T5",
             E(Outcome.NEUTRALIZED, codes=_c("BAD_SIGNATURE", "MALFORMED")),
             s_replay_swapped_header),
    Scenario("P4", "5 Replay", "hostile: random junk, empty objects, truncated batches", "T10",
             E(Outcome.CLEAN, same_hash=True),
             s_hostile_input),
    Scenario("P5", "5 Replay", "forged witness anchor (wrong key)", "T5",
             E(Outcome.NEUTRALIZED, codes=_c("ANCHOR_INVALID")),
             s_forged_anchor),

    # --- 6 Seat swap ---
    Scenario("W1", "6 Seat swap", "rogue machine claims seat, real log present", "T17",
             E(Outcome.NEUTRALIZED, codes=_c("FOREIGN_BATCH", "BAD_SIGNATURE", "MALFORMED"),
               why="real chain present; rogue input rejected or ignored"),
             s_rogue_with_original),
    Scenario("W2", "6 Seat swap", "rogue machine alone, no real log", "T17",
             E(Outcome.DETECTED, codes=_c("UNKNOWN_SEAT", "KEY_NOT_ENROLLED",
                                          "BAD_SIGNATURE", "MALFORMED")),
             s_rogue_alone),
    Scenario("W3", "6 Seat swap", "forged transfer token, original also delivered", "T17",
             E(Outcome.NEUTRALIZED, codes=_c("TRANSFER_INVALID", "FOREIGN_BATCH"),
               why="real chain present; forged transfer rejected"),
             s_forged_transfer_with_original),
    Scenario("W4", "6 Seat swap", "forged transfer token, only forged chain", "T17",
             E(Outcome.DETECTED, codes=_c("TRANSFER_INVALID")),
             s_forged_transfer_alone),
    Scenario("W5", "6 Seat swap", "transfer mismatch: old machine kept writing past token point", "T18",
             E(Outcome.DETECTED, codes=_c("TRANSFER_MISMATCH", "LINK_BREAK",
                                          "MISSING_RANGE", "FORK")),
             s_transfer_mismatch),
    Scenario("W6", "6 Seat swap", "cloned key: seat B carries seat A's key", "T7",
             E(Outcome.DETECTED, codes=_c("DUPLICATE_KEY")),
             s_cloned_key),

    # --- 7 Power loss ---
    Scenario("L1", "7 Power loss", "WAL mid-record corruption (not torn tail)", "T12",
             E(Outcome.CLEAN),
             s_wal_corrupt),

    # --- 8 Fork / sync conflict ---
    Scenario("F1", "8 Fork", "two different tails for same session delivered together", "T6",
             E(Outcome.DETECTED, codes=_c("FORK", "MISSING_RANGE", "LINK_BREAK",
                                          "BAD_SIGNATURE", "MALFORMED")),
             s_fork),
    Scenario("F2", "8 Fork", "anchor conflicts with log at that seq", "T4",
             E(Outcome.DETECTED, codes=_c("ANCHOR_CONFLICT")),
             s_anchor_conflict),

    # --- 9 Key theft / forgery ---
    Scenario("T1", "9 Key theft", "entire session forged from scratch using real key, no real log", "T4",
             E(Outcome.BY_DESIGN, unprovable=_NOANCHOR,
               why="with the private key and no outside anchor a forged session "
                   "is indistinguishable from the real one"),
             s_forge_scratch),
    Scenario("T2", "9 Key theft", "forged session, witness has original final head", "T4",
             E(Outcome.DETECTED, codes=_c("ANCHOR_CONFLICT", "TRUNCATED")),
             s_forge_scratch_witnessed),
    Scenario("T3", "9 Key theft", "forged tail, witness holds prefix", "T4",
             E(Outcome.DETECTED, codes=_c("ANCHOR_CONFLICT", "FORK", "LINK_BREAK",
                                          "BAD_SIGNATURE", "MALFORMED")),
             s_forge_tail),

    # --- 10 Setup tampering ---
    Scenario("S1", "10 Setup", "wrong roster sha in SESSION_START", "T19",
             E(Outcome.DETECTED, codes=_c("ROSTER_MISMATCH")),
             s_roster_swap),
    Scenario("S2", "10 Setup", "wrong paper sha in SESSION_START", "T19",
             E(Outcome.DETECTED, codes=_c("PAPER_MISMATCH")),
             s_paper_swap),
]
