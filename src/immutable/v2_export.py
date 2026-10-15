"""Safe adapter from a v2 server export to the existing Store ingestion API.

The adapter never rewrites signed batch or acknowledgement bytes.  It imports only
artifacts the current Store can authenticate, archives the rest for a later v2-aware
verifier, and reports unsupported artifacts rather than silently weakening evidence.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path


class ExportError(ValueError):
    pass


def ingest(store, path: str | Path) -> dict[str, int]:
    root = Path(path)
    if not root.is_dir():
        raise ExportError("v2 export must be a directory")
    counts: Counter[str] = Counter()
    groups = (("batches", "batch"), ("acks", "anchor"), ("anchors", "anchor"),
              ("manifests", "manifest"), ("blobs", "blob"))
    for dirname, kind in groups:
        directory = root / dirname
        if not directory.is_dir():
            continue
        for item in sorted(p for p in directory.rglob("*") if p.is_file() and not p.is_symlink()):
            if kind == "batch":
                result = store.ingest_batch(item.read_bytes())
            elif kind == "anchor":
                result = store.ingest_anchor(item.read_bytes())
            elif kind == "manifest":
                result = store.ingest_manifest(item.read_bytes())
            else:
                result = store.ingest_blob(item.read_bytes(), expect=item.name)
            counts[f"{kind}:{result.status}"] += 1
    # These are intentionally retained as source material.  Existing verifier logic
    # does not interpret FINAL/journal/config documents, so the adapter never claims it did.
    for dirname in ("configs", "incidents", "journals", "finals", "late_tail"):
        directory = root / dirname
        if directory.is_dir():
            counts["archived:" + dirname] += sum(1 for p in directory.rglob("*") if p.is_file())
    return dict(sorted(counts.items()))
