"""fsys.py: the disk, as the WAL is allowed to see it.

Two implementations of the same five calls:

  RealFS   : what runs on a lab machine. write() reaches the page cache, only
             sync() reaches the platter.
  FaultFS  : an in-memory disk with a memory. Each file has a durable part and a
             pending (unsynced) part. crash() decides what survived: nothing
             pending, a random byte-prefix of it, a prefix plus a zero-filled
             tail (delayed allocation), or all of it.

kill -9 does not test power loss, because the OS page cache survives it. This does.
"""
from __future__ import annotations

import os
import random
from typing import Protocol


class Handle(Protocol):
    def write(self, data: bytes) -> None: ...
    def sync(self) -> None: ...
    def close(self) -> None: ...


class FS(Protocol):
    def exists(self, path: str) -> bool: ...
    def read(self, path: str) -> bytes: ...
    def open_append(self, path: str, *, create: bool = False) -> Handle: ...
    def truncate(self, path: str, size: int) -> None: ...   # durable on return
    def sync_dir(self, path: str) -> None: ...               # makes path's entry durable


_BIN = getattr(os, "O_BINARY", 0)


class _RealHandle:
    def __init__(self, fd: int):
        self._fd = fd

    def write(self, data: bytes) -> None:
        view = memoryview(data)
        while view:                       # os.write may be partial
            n = os.write(self._fd, view)
            view = view[n:]

    def sync(self) -> None:
        os.fsync(self._fd)

    def close(self) -> None:
        os.close(self._fd)


class RealFS:
    def exists(self, path: str) -> bool:
        return os.path.exists(path)

    def read(self, path: str) -> bytes:
        with open(path, "rb") as f:
            return f.read()

    def open_append(self, path: str, *, create: bool = False) -> Handle:
        flags = os.O_WRONLY | os.O_APPEND | _BIN
        if create:
            flags |= os.O_CREAT | os.O_EXCL          # refuse to reuse a log
        return _RealHandle(os.open(path, flags, 0o600))

    def truncate(self, path: str, size: int) -> None:
        fd = os.open(path, os.O_WRONLY | _BIN)
        try:
            os.ftruncate(fd, size)
            os.fsync(fd)
        finally:
            os.close(fd)

    def sync_dir(self, path: str) -> None:
        d = os.path.dirname(os.path.abspath(path))
        try:
            fd = os.open(d, os.O_RDONLY)
        except OSError:                              # Windows: cannot open a dir
            return
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


# ---------------------------------------------------------------- fault layer

class _F:
    __slots__ = ("durable", "pending", "created_durable")

    def __init__(self):
        self.durable = bytearray()
        self.pending = bytearray()
        self.created_durable = False


class _FaultHandle:
    def __init__(self, fs: "FaultFS", f: _F):
        self._fs, self._f = fs, f

    def write(self, data: bytes) -> None:
        self._f.pending += data

    def sync(self) -> None:
        fs = self._fs
        fs.syncs += 1
        if fs.fail_sync_at is not None and fs.syncs == fs.fail_sync_at:
            raise OSError(5, "injected fsync failure")
        if not fs.lie_about_fsync:
            self._f.durable += self._f.pending
            self._f.pending.clear()

    def close(self) -> None:
        pass


class FaultFS:
    """lie_about_fsync=True models a disk whose write cache ignores flushes.
    We cannot defend against that; the fuzzer uses it to show what the loss looks
    like (a recovered chain shorter than what was acknowledged)."""

    def __init__(self, rng: random.Random | None = None, *,
                 lie_about_fsync: bool = False, fail_sync_at: int | None = None):
        self.rng = rng or random.Random(0)
        self.files: dict[str, _F] = {}
        self.lie_about_fsync = lie_about_fsync
        self.fail_sync_at = fail_sync_at
        self.syncs = 0

    # -- FS interface
    def exists(self, path: str) -> bool:
        return path in self.files

    def read(self, path: str) -> bytes:
        f = self.files[path]                  # a live process sees its own writes
        return bytes(f.durable) + bytes(f.pending)

    def open_append(self, path: str, *, create: bool = False) -> Handle:
        if create:
            if path in self.files:
                raise FileExistsError(path)
            self.files[path] = _F()
        return _FaultHandle(self, self.files[path])

    def truncate(self, path: str, size: int) -> None:
        f = self.files[path]
        f.durable = bytearray((bytes(f.durable) + bytes(f.pending))[:size])
        f.pending = bytearray()

    def sync_dir(self, path: str) -> None:
        if path in self.files:
            self.files[path].created_durable = True

    # -- fault injection
    def crash(self, mode: str | None = None) -> list[str]:
        """Power cut. Modes: drop | prefix | prefix_zeros | all (random if None)."""
        log = []
        for path, f in list(self.files.items()):
            m = mode or self.rng.choice(("drop", "prefix", "prefix", "prefix_zeros", "all"))
            pend = bytes(f.pending)
            if m == "drop":
                keep = b""
            elif m == "all":
                keep = pend
            else:
                keep = pend[: self.rng.randint(0, len(pend))]    # torn at a random byte
                if m == "prefix_zeros":
                    keep += bytes(self.rng.randint(1, 512))
            f.durable += keep
            f.pending = bytearray()
            if not f.created_durable and self.rng.random() < 0.5:
                del self.files[path]
                log.append(f"{path}: {m}, file entry itself lost")
            else:
                log.append(f"{path}: {m}, {len(keep)} unsynced bytes landed")
        return log

    def flip_bit(self, path: str, offset: int, bit: int = 0) -> None:
        """Silent corruption of durable bytes (for mid-log damage tests)."""
        self.files[path].durable[offset] ^= 1 << bit
