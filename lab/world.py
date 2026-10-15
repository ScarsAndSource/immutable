"""world.py: the simulated lab environment.

World.build() creates all the keys (assessor, witness, 6 enrolled seats,
3 spare seats, 1 rogue machine) and issues a signed roster so every other
lab module can use them without knowing how keys work.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from immutable import hashing, keys
from immutable.roster import Roster, Seat, Witness

EXAM_ID = "EX20260101"
PAPER_CONTENT = b"examination paper v1 -- immutable tamper lab"
WITNESS_ID = "W001"

N_SEATS = 6
N_SPARES = 3


@dataclass
class World:
    exam: str
    paper_sha: str
    assessor: keys.Signer
    witness_signer: keys.Signer
    # seat_ids in sorted order, e.g. ["WS01", "WS02", ...]
    seat_ids: list[str]
    seats: dict[str, keys.Signer]   # ws_id -> Signer
    spare_ids: list[str]
    spares: dict[str, keys.Signer]  # ws_id -> Signer (not on roster)
    rogue: keys.Signer              # not on roster at all
    roster: Roster
    root: Path

    @classmethod
    def build(cls, root: str | Path, *, n_seats: int = N_SEATS,
              n_spares: int = N_SPARES) -> "World":
        root = Path(root)
        assessor = keys.Signer.generate()
        witness_signer = keys.Signer.generate()
        paper_sha = hashing.sha256_hex(PAPER_CONTENT)

        seat_ids = [f"WS{i+1:02d}" for i in range(n_seats)]
        seat_signers = {ws: keys.Signer.generate() for ws in seat_ids}
        seat_objs = [
            Seat(ws_id=ws,
                 pub=seat_signers[ws].pub_hex,
                 candidate=f"C{i+1:03d}")
            for i, ws in enumerate(seat_ids)
        ]

        spare_ids = [f"SP{i+1:02d}" for i in range(n_spares)]
        spare_signers = {ws: keys.Signer.generate() for ws in spare_ids}
        spare_objs = [
            Seat(ws_id=ws, pub=spare_signers[ws].pub_hex, candidate=None)
            for ws in spare_ids
        ]

        witness_obj = Witness(witness_id=WITNESS_ID, pub=witness_signer.pub_hex)

        roster = Roster.build(
            assessor,
            exam_id=EXAM_ID,
            paper_sha256=paper_sha,
            seats=seat_objs + spare_objs,
            witnesses=[witness_obj],
        )

        rogue = keys.Signer.generate()

        return cls(
            exam=EXAM_ID,
            paper_sha=paper_sha,
            assessor=assessor,
            witness_signer=witness_signer,
            seat_ids=seat_ids,
            seats=seat_signers,
            spare_ids=spare_ids,
            spares=spare_signers,
            rogue=rogue,
            roster=roster,
            root=root,
        )
