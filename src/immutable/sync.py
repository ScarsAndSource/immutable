"""Client-side save acknowledgement state machine.

The WAL answers "is this save durable on this workstation?".  ``SyncController``
answers the separate question "may the editor accept another change?".  It sits on
top of the existing :class:`Agent` outbox and :class:`Courier`: a save is editable
only when every sealed event is acknowledged by the remote holder.

This deliberately contains no network protocol details.  The v2 server courier and
the v1 LAN-witness courier expose the same small contract, so the lock behaviour is
identical in online-first and offline-fallback deployments.
"""
from __future__ import annotations

import enum
import threading
import time
from dataclasses import dataclass
from typing import Callable


class SyncState(str, enum.Enum):
    CONNECTING = "connecting"
    SYNCED = "synced"
    PROBING = "probing"
    LOCKED = "locked"
    RESYNC = "resync"
    FINALIZED = "finalized"


class SyncLocked(RuntimeError):
    """Raised when an edit is attempted while its evidence is not acknowledged."""


@dataclass(frozen=True)
class SyncSnapshot:
    state: SyncState
    last_confirmed_seq: int
    last_saved_monotonic: float | None
    next_retry_in_ms: int | None
    detail: str | None


class SyncController:
    """Gate edits after one failed upload and one immediate retry.

    ``flush`` must make all durable WAL records into outbox batches. ``pump`` must
    make one best effort courier pass and return its status.  A pass is successful
    only when the remote holder has acknowledged every sealed record; a merely empty
    local queue is never enough.
    """

    RETRIES_S = (1.0, 2.0, 4.0, 8.0, 10.0)

    def __init__(self, *, flush: Callable[[], object], status: Callable[[], dict],
                 pump: Callable[[], dict], now: Callable[[], float] = time.monotonic):
        self._flush, self._status, self._pump, self._now = flush, status, pump, now
        self._lock = threading.RLock()
        self._state = SyncState.CONNECTING
        self._last_confirmed_seq = -1
        self._last_saved: float | None = None
        self._next_retry: float | None = None
        self._retry_index = 0
        self._detail: str | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def editable(self) -> bool:
        return self._state is SyncState.SYNCED

    def snapshot(self) -> SyncSnapshot:
        with self._lock:
            wait = None if self._next_retry is None else max(0, round((self._next_retry - self._now()) * 1000))
            return SyncSnapshot(self._state, self._last_confirmed_seq, self._last_saved, wait, self._detail)

    def require_editable(self) -> None:
        if not self.editable:
            raise SyncLocked("editing is paused while the last saved change is being confirmed")

    def mark_finalized(self) -> None:
        with self._lock:
            self._state, self._next_retry = SyncState.FINALIZED, None

    def synchronize(self) -> bool:
        """Attempt a save acknowledgement, including the one immediate retry."""
        with self._lock:
            if self._state is SyncState.FINALIZED:
                return False
            if self._attempt():
                self._become_synced(resynced=self._state in (SyncState.LOCKED, SyncState.RESYNC))
                return True
            self._state = SyncState.PROBING
            if self._attempt():
                self._become_synced(resynced=False)
                return True
            self._lock_editor()
            return False

    def tick(self) -> bool:
        """Perform one scheduled locked-state retry, if one is due."""
        with self._lock:
            if self._state is not SyncState.LOCKED or self._next_retry is None or self._now() < self._next_retry:
                return False
            self._state = SyncState.RESYNC
            if self._attempt():
                self._become_synced(resynced=True)
                return True
            self._lock_editor()
            return False

    def start(self, interval_s: float = 0.25) -> None:
        """Retry while the UI is idle; retries still obey the documented backoff."""
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()

        def loop() -> None:
            while not self._stop.wait(interval_s):
                self.tick()

        self._thread = threading.Thread(target=loop, name="immutable-sync", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _attempt(self) -> bool:
        try:
            self._flush()
            courier = self._pump()
            local = self._status()
        except Exception as exc:  # transport failure is intentionally non-fatal to the WAL
            self._detail = f"sync attempt failed: {type(exc).__name__}"
            return False
        if courier.get("rejected"):
            self._detail = "remote holder rejected the pending evidence; call the invigilator"
            return False
        sealed = int(local.get("sealed_upto", -1))
        held = int(courier.get("delivered_upto", -1))
        if held < sealed or int(courier.get("pending", 0)):
            self._detail = courier.get("last_error") or "waiting for remote acknowledgement"
            return False
        self._last_confirmed_seq = max(self._last_confirmed_seq, held)
        return True

    def _become_synced(self, *, resynced: bool) -> None:
        self._state, self._next_retry, self._retry_index, self._detail = SyncState.SYNCED, None, 0, None
        self._last_saved = self._now()

    def _lock_editor(self) -> None:
        delay = self.RETRIES_S[min(self._retry_index, len(self.RETRIES_S) - 1)]
        self._retry_index += 1
        self._state = SyncState.LOCKED
        self._next_retry = self._now() + delay

