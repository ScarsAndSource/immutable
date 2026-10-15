"""submission.py: what was handed in versus what was recorded while working.

The agent writes a canonical manifest and stores each file under its own hash. This
checks the manifest against the SUBMIT event, against the last recorded save of every
path, and against the blob store. The dispute "my last save was deleted" lives in
SUBMISSION_GAP: a path that was saved during the session but is not in the submission.
"""
from __future__ import annotations

from typing import Callable

from . import canon, hashing, policy
from .events import ID_RE, Event
from .findings import Code, Finding


class SubmissionError(ValueError):
    pass


def parse_manifest(raw: bytes) -> dict:
    try:
        m = canon.loads(raw, max_bytes=1 << 20)
    except canon.CanonError as e:
        raise SubmissionError(f"unreadable: {e}") from None
    if not isinstance(m, dict) or set(m) != {"v", "exam_id", "session_id", "ws_id", "files"} or m["v"] != 1:
        raise SubmissionError("manifest must have exactly the v1 fields")
    for k in ("exam_id", "session_id", "ws_id"):
        if not (isinstance(m[k], str) and ID_RE.match(m[k])):
            raise SubmissionError(f"bad {k}")
    files = m["files"]
    if not isinstance(files, list) or len(files) > 500:
        raise SubmissionError("bad file list")
    paths = []
    for e in files:
        if not isinstance(e, dict) or set(e) != {"path", "sha256", "size"} \
                or not policy.is_relpath(e["path"]) or not hashing.is_hash(e["sha256"]) \
                or not policy._uint(e["size"]):
            raise SubmissionError("bad file entry")
        paths.append(e["path"])
    if paths != sorted(paths) or len(set(paths)) != len(paths):
        raise SubmissionError("files must be sorted by path with no duplicates")
    return m


def check(raw: bytes, submit_ev: Event, saves: dict[str, str],
          has_blob: Callable[[str], bool] | None) -> tuple[list[Finding], dict]:
    f: list[Finding] = []
    seq = submit_ev.seq
    stats = {"files": 0, "checked": False}

    def bad(detail: str) -> None:
        f.append(Finding(Code.SUBMISSION_MISMATCH, seq, detail))

    if hashing.sha256_hex(raw) != submit_ev.data["manifest_sha256"]:
        bad("the manifest differs from the fingerprint recorded at SUBMIT")
        return f, stats
    try:
        m = parse_manifest(raw)
    except SubmissionError as e:
        bad(f"the manifest is not valid: {e}")
        return f, stats
    if (m["exam_id"], m["session_id"], m["ws_id"]) != \
            (submit_ev.exam_id, submit_ev.session_id, submit_ev.ws_id):
        bad("the manifest names a different exam, session or seat")
    if len(m["files"]) != submit_ev.data["file_count"]:
        bad("the number of files differs from the count recorded at SUBMIT")

    listed = {e["path"]: e for e in m["files"]}
    for path, e in sorted(listed.items()):
        if saves.get(path) != e["sha256"]:
            bad(f"{path} was submitted with contents that differ from its last recorded save")
        if has_blob is not None and not has_blob(e["sha256"]):
            f.append(Finding(Code.BLOB_MISSING, seq, f"the contents of {path} are not in the evidence store"))
    for path in sorted(set(saves) - set(listed)):
        f.append(Finding(Code.SUBMISSION_GAP, seq, f"{path} was saved during the session but is not in the submission"))
    stats["files"] = len(m["files"])
    stats["checked"] = True
    return f, stats
