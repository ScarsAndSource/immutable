"""simlab.py (B8): a lab of honest students on a virtual clock, running the REAL code.

Real: Agent, Wal (on the fault-injecting FaultFS), Courier, Witness, transfer tokens,
batch sealing, and later reconcile(). Simulated: time, the student, the disk's bad
days, and the file contents. No subprocess is spawned: a "run" is begin_run/end_run
around a virtual duration.

How the virtual clock reaches the real code: the modules read time through
clock.stamp / clock.boot_id / clock.boottime_ns and agent.time.monotonic. World.installed()
swaps those for per-station virtual versions and restores them afterwards. Each station
has its own wall clock (offset, slew, steps, dead RTC), its own uptime and boot id.
The witness reads TRUE time, so station clock faults show up as offsets against it.

fsync is skipped for the OUTBOX files (agent._atomic_write is swapped); the WAL's
fsync semantics are the point of FaultFS and are fully modelled. In-flight appends are
injected before a power cut so the torn-tail path is really exercised.

Results are SIMULATED. They show the pipeline does not accuse honest sessions under
the faults modelled here, not under every fault reality has.
"""
from __future__ import annotations

import os
import random
import shutil
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from . import agent as agent_mod
from . import clock, hashing, keys, transfer, wal as wal_mod
from .batch import Batch
from .clockcheck import ClockPolicy
from .courier import Courier
from .faults import make_plan
from .fsys import FaultFS
from .net import LocalTransport
from .reconcile import reconcile
from .roster import Roster, Seat, Witness as RWitness
from .witness import Witness
from .workspace import FileInfo, Listing

START_NS = 1_760_000_000 * 1_000_000_000
RTC_BOGUS_NS = 946_684_800 * 1_000_000_000
PAPER = b"%PDF-sim-paper\n"
INITIAL = {"main.py": b"print('hello')\n", "notes.txt": b"", "util.py": b"def f(x):\n    return x\n"}


def _signer(seed: int, name: str) -> keys.Signer:
    return keys.Signer.from_seed_hex(hashing.sha256_hex(f"immutable-sim/{seed}/{name}".encode()))


class MemWorkspace:
    """Duck-typed Workspace: scan / collect / snapshot over a dict."""

    def __init__(self, files: dict):
        self.files: dict = {}
        self._info: dict = {}
        for p, d in files.items():
            self.write(p, d)

    def write(self, path: str, data: bytes) -> None:
        self.files[path] = data
        self._info[path] = FileInfo(hashing.sha256_hex(data), len(data))

    def delete(self, path: str) -> None:
        self.files.pop(path, None)
        self._info.pop(path, None)

    def scan(self) -> Listing:
        return Listing(dict(sorted(self._info.items())), [])

    def collect(self, sink) -> Listing:
        for p in sorted(self.files):
            sink(p, self.files[p])
        return self.scan()

    def snapshot(self, dst) -> Listing:          # nothing executes: no need to write files
        return self.scan()


class _TimeShim:
    def __init__(self, world):
        self._w = world

    def monotonic(self) -> float:
        return self._w.true_ns / 1e9


def _fast_write(path, data: bytes) -> None:
    p = Path(path)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, p)


class World:
    def __init__(self, duration_s: int, tick_s: int, outages: list):
        self.true_ns = START_NS
        self.t = 0
        self.tick_idx = 0
        self.duration_s, self.tick_s = duration_s, tick_s
        self.tick_ns = tick_s * 1_000_000_000
        self.outages = outages
        self.cur = None

    def tick(self) -> None:
        self.true_ns += self.tick_ns
        self.t += self.tick_s
        self.tick_idx += 1

    def in_outage(self) -> bool:
        return any(a <= self.t < b for a, b in self.outages)

    @contextmanager
    def installed(self):
        saved = (clock.stamp, clock.boot_id, clock.boottime_ns, agent_mod.time, agent_mod._atomic_write)
        clock.stamp = lambda: self.cur.stamp()
        clock.boot_id = lambda: self.cur.boot_id
        clock.boottime_ns = lambda: self.cur.up_ns
        agent_mod.time = _TimeShim(self)
        agent_mod._atomic_write = _fast_write
        try:
            yield
        finally:
            (clock.stamp, clock.boot_id, clock.boottime_ns,
             agent_mod.time, agent_mod._atomic_write) = saved


class Station:
    def __init__(self, lab, ws_id: str, plan, rng: random.Random):
        self.lab, self.world, self.rng, self.plan = lab, lab.world, rng, plan
        self.ws_id = ws_id
        self.session_id = f"S-{ws_id}"
        self.signer = _signer(lab.seed, ws_id)
        self.mem = MemWorkspace(INITIAL)
        self.fs = FaultFS(random.Random(rng.random()), lie_about_fsync=plan.lying_disk)
        self.dir = lab.root / ws_id
        self.dirs = [self.dir]
        self.true_offset_ns = rng.randint(-500, 500) * 1_000_000
        self.wall_ns = self.world.true_ns + self.true_offset_ns
        self.up_ns = rng.randint(60, 600) * 1_000_000_000
        self.boot_n = 0
        self.boot_id = self._bid()
        self.slew = plan.slew_ppm
        self.pending = list(plan.faults)
        self.agent = self.courier = None
        self.down_until = self.sleep_until = self.ntp_fix_at = None
        self.down_start = 0
        self.sleep_ns = 0
        self.restart_kind, self.restart_p = "", {}
        self.run = None
        self.done = False
        self.applied: list = []
        self.ws_ids = [ws_id]
        self.scratch = 0

    # ----- clocks
    def _bid(self) -> str:
        return f"{self.ws_id.lower()}-b{self.boot_n}"

    def stamp(self) -> tuple:
        return self.wall_ns // 1_000_000, self.up_ns

    def advance(self, dt_ns: int) -> None:
        self.up_ns += dt_ns
        self.wall_ns += dt_ns + dt_ns * self.slew // 1_000_000

    # ----- lifecycle
    def open(self, token: bytes | None = None) -> None:
        lab = self.lab
        self.agent = agent_mod.Agent.open(
            evidence_dir=self.dir, workspace=self.mem, exam_id=lab.exam_id,
            session_id=self.session_id, ws_id=self.ws_id, signer=self.signer,
            paper_sha256=lab.paper_sha, roster_sha256=lab.roster.id, fs=self.fs,
            heartbeat_s=30.0, checkpoint_every=64, transfer_token=token,
            assessor_pub=lab.assessor.pub_hex if token else None)
        if lab.witness is not None:
            self.courier = Courier(
                outbox=self.dir / "outbox", anchors_dir=self.dir / "anchors",
                state_path=self.dir / "courier.json", transport=lab.transport(),
                signer=self.signer, exam_id=lab.exam_id, session_id=self.session_id,
                ws_id=self.ws_id, ping_every_s=10.0, now=lambda: self.world.true_ns / 1e9)

    def tick(self) -> None:
        w = self.world
        if self.done:
            return
        if self.down_until is not None:
            if w.true_ns < self.down_until:
                return
            self._come_up()
        elif self.sleep_until is not None:
            if w.true_ns < self.sleep_until:
                return
            self.advance(self.sleep_ns)
            self.sleep_until = None
        else:
            self.advance(w.tick_ns)
        if self.ntp_fix_at is not None and w.true_ns >= self.ntp_fix_at:
            self.wall_ns = w.true_ns + self.true_offset_ns
            self.ntp_fix_at = None
            self.applied.append("ntp_fix")
        while self.pending and self.pending[0].t <= w.t:
            self._apply(self.pending.pop(0))
            if self.down_until is not None or self.sleep_until is not None or self.agent is None:
                return
        if self.agent is None:
            return
        rng = self.rng
        if rng.random() < 0.04:
            p = rng.choice(sorted(self.mem.files))
            self.mem.write(p, self.mem.files[p] + b"x=%d\n" % rng.randint(0, 10**6))
        if self.run is None and rng.random() < 0.02:
            tk = self.agent.begin_run("main.py")
            dur = rng.randint(1, 8)
            self.run = (tk, w.true_ns + dur * 10**9, dur)
        if self.run is not None and w.true_ns >= self.run[1]:
            self._finish_run()
        if rng.random() < 0.002:
            scr = sorted(p for p in self.mem.files if p.startswith("scratch_"))
            if scr and rng.random() < 0.5:
                self.mem.delete(rng.choice(scr))
            else:
                self.scratch += 1
                self.mem.write(f"scratch_{self.scratch}.py", b"pass\n")
        self.agent.tick()
        if self.courier and w.tick_idx % 2 == 0:
            self.courier.pump_once()
        if w.t >= w.duration_s:
            self._submit()

    # ----- student
    def _finish_run(self) -> None:
        tk, _, dur = self.run
        self.agent.end_run(tk, self.rng.choice((0, 0, 0, 1)),
                           hashing.sha256_hex(b"out%d" % self.rng.randint(0, 5)),
                           dur * 1000 + self.rng.randint(0, 900))
        self.run = None

    def _submit(self) -> None:
        if self.run is not None:
            self._finish_run()
        self.agent.submit()
        if self.courier:
            self.courier.pump_once()
        self.done = True

    # ----- faults
    def _apply(self, f) -> None:
        self.applied.append(f.kind)
        p, k = f.params, f.kind
        if k == "ntp_step":
            self.wall_ns += p["delta_ms"] * 1_000_000
        elif k == "vm_pause":
            self.wall_ns += p["pause_s"] * 10**9
        elif k == "suspend":
            self.sleep_ns = p["sleep_s"] * 10**9
            self.sleep_until = self.world.true_ns + self.sleep_ns
        elif k == "seat_swap":
            self._swap()
        else:
            self._go_down(k, p)

    def _drop_run(self) -> None:
        if self.run is not None:
            shutil.rmtree(self.run[0].dir, ignore_errors=True)
            self.run = None

    def _go_down(self, kind: str, p: dict) -> None:
        self._drop_run()
        ag = self.agent
        if kind in ("clean_restart", "reboot"):
            ag.close()
        elif kind == "agent_crash":
            self.fs.crash("all")
        else:                                           # power_cut: an append is in flight
            try:
                w = ag._wal
                ev = w._w.append("HEARTBEAT", {})
                w._h.write(wal_mod.frame(ev.canonical()))
            except Exception:
                pass
            self.fs.crash()
        self.agent = self.courier = None
        self.down_start = self.world.true_ns
        self.down_until = self.world.true_ns + p["down_s"] * 10**9
        self.restart_kind, self.restart_p = kind, p

    def _come_up(self) -> None:
        w, p = self.world, self.restart_p
        elapsed = w.true_ns - self.down_start
        self.down_until = None
        if self.restart_kind in ("reboot", "power_cut"):
            self.boot_n += 1
            self.boot_id = self._bid()
            self.up_ns = self.rng.randint(8, 25) * 10**9
            if p.get("rtc_dead"):
                self.wall_ns = RTC_BOGUS_NS + self.up_ns
                if p.get("fix_after_s"):
                    self.ntp_fix_at = w.true_ns + p["fix_after_s"] * 10**9
            else:
                self.wall_ns += elapsed
        else:
            self.advance(elapsed)
        self.open()

    def _swap(self) -> None:
        lab = self.lab
        self._drop_run()
        self.agent.flush()
        st = self.agent.status()
        if self.courier:
            self.courier.pump_once()
        self.agent.close()
        old = self.ws_id
        new = f"{old}X"
        sg = _signer(lab.seed, new)
        token = transfer.issue(lab.assessor, exam_id=lab.exam_id, session_id=self.session_id,
                               from_ws_id=old, from_last_seq=st["last_seq"], from_head=st["head"],
                               to_ws_id=new, to_pub=sg.pub_hex)
        self.ws_id, self.signer = new, sg
        self.ws_ids.append(new)
        self.dir = lab.root / new
        self.dirs.append(self.dir)
        self.fs = FaultFS(random.Random(self.rng.random()), lie_about_fsync=self.plan.lying_disk)
        self.boot_n += 1
        self.boot_id = self._bid()
        self.up_ns = self.rng.randint(8, 25) * 10**9
        self.true_offset_ns = self.rng.randint(-500, 500) * 1_000_000
        self.wall_ns = self.world.true_ns + self.true_offset_ns
        self.slew = self.rng.randint(-150, 150)
        self.open(token)


@dataclass
class LabResult:
    seed: int
    roster_raw: bytes
    assessor_pub: str
    batches: list
    anchors: list
    manifests: list
    blobs: set
    stations: dict
    witness_report: dict | None


class _Lab:
    def __init__(self, seed, n_seats, duration_s, tick_s, profile, lying_disk, witness_on,
                 outage_per_hour, baseline_ppm, root: Path):
        self.seed, self.root = seed, root
        rng = random.Random(seed)
        outages = []
        if witness_on:
            for _ in range(_poisson_n(rng, outage_per_hour * duration_s / 3600)):
                a = rng.randint(120, max(121, duration_s - 300))
                outages.append((a, a + rng.randint(30, 900)))
        self.world = World(duration_s, tick_s, outages)
        self.exam_id = f"EX{seed}"
        self.paper_sha = hashing.sha256_hex(PAPER)
        self.assessor = _signer(seed, "ASSESSOR")
        wsig = _signer(seed, "WITNESS")
        ids = [f"WS{i + 1:02d}" for i in range(n_seats)]
        self.roster = Roster.build(
            self.assessor, exam_id=self.exam_id, paper_sha256=self.paper_sha,
            seats=[Seat(i, _signer(seed, i).pub_hex, f"C{k + 1:03d}") for k, i in enumerate(ids)],
            witnesses=[RWitness("W1", wsig.pub_hex)], issued_ms=START_NS // 10**6)
        self.witness = Witness(self.roster, wsig, "W1", directory=None,
                               now_ms=lambda: self.world.true_ns // 10**6) if witness_on else None
        self.stations = [Station(self, i, make_plan(random.Random(f"{seed}/{i}"), profile, duration_s,
                                                    baseline_ppm=baseline_ppm, lying_disk=lying_disk),
                                 random.Random(f"{seed}/{i}/student")) for i in ids]

    def transport(self):
        return LocalTransport(self.witness, available=lambda: not self.world.in_outage())

    def run(self) -> None:
        w = self.world
        for st in self.stations:
            w.cur = st
            st.open()
        while True:
            w.tick()
            for st in self.stations:
                w.cur = st
                st.tick()
            if all(s.done for s in self.stations) or w.t > w.duration_s + 1800:
                break
        for _ in range(120):                              # courier keeps draining after submit
            w.tick()
            if w.tick_idx % 2:
                continue
            for st in self.stations:
                w.cur = st
                if st.courier:
                    st.courier.pump_once()

    def collect(self) -> LabResult:
        batches, manifests, blobs, stations = [], [], set(), {}
        for st in self.stations:
            for d in st.dirs:
                batches += [p.read_bytes() for p in sorted((d / "outbox").glob("*.batch.json"))]
                m = d / "submission" / "manifest.json"
                if m.exists():
                    manifests.append(m.read_bytes())
                bd = d / "submission" / "blobs"
                if bd.exists():
                    blobs |= {p.name for p in bd.iterdir()}
            stations[st.session_id] = {"ws": st.ws_ids, "faults": sorted(set(st.applied)),
                                       "slew_ppm": st.slew, "done": st.done}
        anchors = list(dict.fromkeys(self.witness.issued)) if self.witness else []
        return LabResult(self.seed, self.roster.raw, self.assessor.pub_hex, batches, anchors,
                         manifests, blobs, stations,
                         self.witness.report() if self.witness else None)


def _poisson_n(rng: random.Random, lam: float) -> int:
    import math
    limit, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= rng.random()
        if p <= limit:
            return k
        k += 1


def simulate_lab(seed: int, *, n_seats: int = 6, duration_s: int = 10_800, profile: str = "typical",
                 tick_s: int = 5, lying_disk: bool = False, witness_on: bool = True,
                 outage_per_hour: float = 0.5, baseline_ppm: int = 150,
                 workdir: str | None = None) -> LabResult:
    base = workdir or ("/dev/shm" if os.path.isdir("/dev/shm") else None)
    with tempfile.TemporaryDirectory(prefix="cs-lab-", dir=base) as tmp:
        lab = _Lab(seed, n_seats, duration_s, tick_s, profile, lying_disk, witness_on,
                   outage_per_hour, baseline_ppm, Path(tmp))
        with lab.world.installed():
            lab.run()
        return lab.collect()


def reconcile_lab(lab: LabResult, *, with_anchors: bool = True, policy: ClockPolicy = ClockPolicy()):
    roster = Roster.parse(lab.roster_raw, trusted_assessor=lab.assessor_pub)
    blobs = lab.blobs
    return reconcile(lab.batches, roster, anchors=lab.anchors if with_anchors else [],
                     manifests=lab.manifests, has_blob=lambda s: s in blobs, policy=policy)


def trunks(lab: LabResult) -> dict:
    by: dict = {}
    for raw in lab.batches:
        b = Batch.parse(raw)
        d = by.setdefault((b.header["session_id"], b.header["ws_id"]), {})
        for e in b.events:
            d[e.seq] = e
    return {k: [v[s] for s in sorted(v)] for k, v in by.items()}
