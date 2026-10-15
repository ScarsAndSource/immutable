"""courier.py (B9): ships sealed batches to the witness and never loses its place.

Lives beside the agent (same process in lab_agent, same OS user, same threat T14: a
student can stop it; the witness's contact record and the unanchored-tail statement
are what make that visible, not any promise here).

  * queue and retry: network trouble leaves batches in the outbox; the next pump
    resends them, with backoff in the background thread
  * 4xx answers are permanent: recorded in `rejected`, shown to the student/UI, not
    retried. A 409 here means the witness holds a DIFFERENT history: that is evidence
    and the student should call the invigilator.
  * anchors the witness returns are saved beside the evidence (anchors/*.anchor.json),
    so assessor ingest of the whole directory picks them up. The witness keeps its own
    copy too; deleting the local files destroys nothing.
  * heartbeat: a signed ping every ping_every_s. The reply says how far the witness
    thinks it has; if that is behind what we delivered (witness lost its disk), the
    courier forgets the difference and resends. Nothing is trusted to stay delivered.
"""
from __future__ import annotations

import threading
import time
from pathlib import Path

from . import agent as _agent
from . import anchor, canon, clock
from .agent import _BATCH_FILE
from .keys import Signer
from .witness import make_ping

_PERMANENT = (400, 403, 409, 413, 422)


def _seqs(name: str) -> tuple[int, int] | None:
    m = _BATCH_FILE.match(name)
    return (int(m.group(1)), int(m.group(2))) if m else None


class Courier:
    def __init__(self, *, outbox: Path, anchors_dir: Path, state_path: Path, transport,
                 signer: Signer, exam_id: str, session_id: str, ws_id: str,
                 ping_every_s: float = 10.0, now=time.monotonic):
        self.outbox, self.anchors, self.state_path = Path(outbox), Path(anchors_dir), Path(state_path)
        self.anchors.mkdir(parents=True, exist_ok=True)
        self.transport, self.signer = transport, signer
        self.exam_id, self.session_id, self.ws_id = exam_id, session_id, ws_id
        self.ping_every_s, self.now = ping_every_s, now
        self._born = now()
        self._last_ping = float("-inf")
        self.last_error: str | None = None
        self.last_ok: float | None = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.delivered: set[str] = set()
        self.rejected: dict[str, str] = {}
        self._load()

    # ------------------------------------------------------------------ state
    def _load(self) -> None:
        try:
            obj = canon.loads(self.state_path.read_bytes(), max_bytes=1 << 20)
            if isinstance(obj, dict) and isinstance(obj.get("delivered"), list) \
                    and isinstance(obj.get("rejected"), dict):
                self.delivered = {n for n in obj["delivered"] if isinstance(n, str)}
                self.rejected = {k: v for k, v in obj["rejected"].items() if isinstance(v, str)}
        except (OSError, canon.CanonError):
            pass

    def _persist(self) -> None:
        _agent._atomic_write(self.state_path, canon.dumps(
            {"delivered": sorted(self.delivered), "rejected": dict(sorted(self.rejected.items()))}))

    # ------------------------------------------------------------------- work
    def _save_anchor(self, body: bytes) -> None:
        a = anchor.parse(body)
        if (a.session_id, a.ws_id) == (self.session_id, self.ws_id):
            _agent._atomic_write(self.anchors / f"{a.id}.anchor.json", a.to_bytes())

    def _names(self) -> list[str]:
        return sorted(p.name for p in self.outbox.iterdir() if _BATCH_FILE.match(p.name))

    def _maybe_ping(self, names: list[str]) -> None:
        t = self.now()
        if t - self._last_ping < self.ping_every_s:
            return
        top = max((_seqs(n)[1] for n in names), default=-1)
        raw = make_ping(self.signer, exam_id=self.exam_id, session_id=self.session_id,
                        ws_id=self.ws_id, boot_id=clock.boot_id(),
                        boot_ns=clock.boottime_ns(), last_seq=top)
        status, body = self.transport.ping(raw)
        self._last_ping = t
        if status == 200:
            try:
                held = canon.loads(body, max_bytes=2048)["held_upto"]
            except (canon.CanonError, KeyError, TypeError):
                return
            for n in list(self.delivered):               # witness is behind: resend the gap
                s = _seqs(n)
                if s and s[1] > held:
                    self.delivered.discard(n)

    def pump_once(self) -> dict:
        with self._lock:
            try:
                names = self._names()
                for n in names:
                    if n in self.delivered or n in self.rejected:
                        continue
                    status, body = self.transport.submit((self.outbox / n).read_bytes())
                    if status == 200:
                        self._save_anchor(body)
                        self.delivered.add(n)
                    elif status in _PERMANENT:
                        try:
                            d = canon.loads(body, max_bytes=2048)
                            self.rejected[n] = f"{status} {d.get('error')}: {d.get('detail')}"
                        except canon.CanonError:
                            self.rejected[n] = f"{status}"
                    else:
                        raise OSError(f"witness answered {status}")
                self._maybe_ping(names)
                self.last_error, self.last_ok = None, self.now()
            except OSError as e:
                self.last_error = str(e) or e.__class__.__name__
            self._persist()
            return self.status()

    def status(self) -> dict:
        names = self._names()
        done = [_seqs(n)[1] for n in names if n in self.delivered]
        return {"delivered_upto": max(done, default=-1),
                "pending": sum(1 for n in names if n not in self.delivered and n not in self.rejected),
                "rejected": dict(self.rejected), "last_error": self.last_error,
                "unreachable_s": int(self.unreachable_s())}

    def unreachable_s(self) -> float:
        if self.last_error is None:
            return 0.0
        return self.now() - (self.last_ok if self.last_ok is not None else self._born)

    # ----------------------------------------------------------------- thread
    def start(self, interval: float = 2.0) -> None:
        def loop():
            fails = 0
            while not self._stop.wait(min(30.0, interval * (2 ** min(fails, 4)))):
                self.pump_once()
                fails = fails + 1 if self.last_error else 0
        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
