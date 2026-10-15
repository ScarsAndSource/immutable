"""workspace.py: what the student has on disk, reduced to fingerprints.

We hash bytes we actually read, then forward those same bytes to whoever asked
(a run snapshot, a submission blob). So "the hash we recorded" and "the bytes
that were used" cannot drift apart, even if the student saves mid-read.

Nothing is silently ignored except __pycache__ and *.pyc. Anything else we cannot
fingerprint (symlink, huge file, odd filename) is listed in `skipped`, so the UI
can tell the student their file is not part of the evidence.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from . import policy
from .hashing import sha256_hex

MAX_FILE = 2 << 20          # 2 MiB per file
MAX_FILES = 500
MAX_DEPTH = 8
SKIP_DIRS = frozenset({"__pycache__"})
RECENT_NS = 2_000_000_000   # mtimes younger than 2s are not trusted as a cache key


@dataclass(frozen=True)
class FileInfo:
    sha256: str
    size: int


@dataclass
class Listing:
    files: dict[str, FileInfo]
    skipped: list[str]


class Workspace:
    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            raise NotADirectoryError(str(self.root))
        self._cache: dict[str, tuple[tuple[int, int], FileInfo]] = {}

    def _enumerate(self):
        found, skipped = [], []
        stack = [(str(self.root), "", 0)]
        while stack:
            d, prefix, depth = stack.pop()
            try:
                with os.scandir(d) as it:
                    entries = list(it)
            except OSError:
                continue
            for e in entries:
                rel = prefix + e.name
                try:
                    if e.is_symlink():
                        skipped.append(f"{rel}: symlink")
                        continue
                    if e.is_dir(follow_symlinks=False):
                        if e.name in SKIP_DIRS:
                            continue
                        if depth >= MAX_DEPTH:
                            skipped.append(f"{rel}/: nested too deep")
                            continue
                        stack.append((e.path, rel + "/", depth + 1))
                        continue
                    if not e.is_file(follow_symlinks=False) or e.name.endswith(".pyc"):
                        continue
                    st = e.stat(follow_symlinks=False)
                except OSError:
                    continue
                if not policy.is_relpath(rel):
                    skipped.append(f"{rel}: filename not supported")
                elif st.st_size > MAX_FILE:
                    skipped.append(f"{rel}: larger than {MAX_FILE >> 20} MiB")
                else:
                    found.append((rel, e.path, st))
        found.sort(key=lambda t: t[0])
        for rel, _, _ in found[MAX_FILES:]:
            skipped.append(f"{rel}: over the {MAX_FILES}-file limit")
        return found[:MAX_FILES], skipped

    def scan(self) -> Listing:
        """Cheap poll: rehash only files whose (mtime, size) changed."""
        found, skipped = self._enumerate()
        files: dict[str, FileInfo] = {}
        now = time.time_ns()
        for rel, path, st in found:
            key = (st.st_mtime_ns, st.st_size)
            hit = self._cache.get(rel)
            if hit and hit[0] == key and now - st.st_mtime_ns > RECENT_NS:
                files[rel] = hit[1]
                continue
            try:
                data = Path(path).read_bytes()
            except OSError:
                skipped.append(f"{rel}: unreadable")
                continue
            info = FileInfo(sha256_hex(data), len(data))
            self._cache[rel] = (key, info)
            files[rel] = info
        return Listing(files, skipped)

    def collect(self, sink: Callable[[str, bytes], None]) -> Listing:
        """Read every eligible file once; hand (rel, bytes) to sink; return fingerprints."""
        found, skipped = self._enumerate()
        files: dict[str, FileInfo] = {}
        for rel, path, _ in found:
            try:
                data = Path(path).read_bytes()
            except OSError:
                skipped.append(f"{rel}: unreadable")
                continue
            if len(data) > MAX_FILE:
                skipped.append(f"{rel}: larger than {MAX_FILE >> 20} MiB")
                continue
            sink(rel, data)
            files[rel] = FileInfo(sha256_hex(data), len(data))
        return Listing(files, skipped)

    def snapshot(self, dst: str | Path) -> Listing:
        """Copy the workspace to dst (a run sandbox) and fingerprint what was copied."""
        dst = Path(dst)

        def sink(rel: str, data: bytes) -> None:
            p = dst / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)

        return self.collect(sink)
