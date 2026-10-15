"""findings.py: the verifier speaks in codes, humans read the sentences.

Codes are stable (reports, UI copy and tests key off them). A finding says what is
inconsistent and where. It never says who is guilty.

SUSPECT findings drive the headline verdict TAMPER_SUSPECTED (shown to people as
"evidence inconsistent"). NOTE findings explain benign faults and ignored input and
can never change a verdict. Anything a LAN attacker can cause by injecting files is
a NOTE by construction, so nobody is accused over traffic they never sent.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    SUSPECT = "suspect"
    NOTE = "note"


class Code(str, Enum):
    # inside one batch
    MALFORMED = "MALFORMED"
    BAD_SIGNATURE = "BAD_SIGNATURE"
    SIGNER_MISMATCH = "SIGNER_MISMATCH"
    WRONG_CONTEXT = "WRONG_CONTEXT"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    SEQ_GAP = "SEQ_GAP"
    CHAIN_BREAK = "CHAIN_BREAK"
    HEADER_MISMATCH = "HEADER_MISMATCH"
    # intake
    WRONG_EXAM = "WRONG_EXAM"
    FOREIGN_BATCH = "FOREIGN_BATCH"
    BATCH_DEFECT = "BATCH_DEFECT"
    ANCHOR_INVALID = "ANCHOR_INVALID"
    # identity
    UNKNOWN_SEAT = "UNKNOWN_SEAT"
    KEY_NOT_ENROLLED = "KEY_NOT_ENROLLED"
    DUPLICATE_KEY = "DUPLICATE_KEY"
    TRANSFER_INVALID = "TRANSFER_INVALID"
    TRANSFER_MISMATCH = "TRANSFER_MISMATCH"
    # chain
    FORK = "FORK"
    MISSING_RANGE = "MISSING_RANGE"
    LINK_BREAK = "LINK_BREAK"
    # protocol
    BAD_START = "BAD_START"
    ROSTER_MISMATCH = "ROSTER_MISMATCH"
    PAPER_MISMATCH = "PAPER_MISMATCH"
    BOOT_UNMARKED = "BOOT_UNMARKED"
    RECOVERY_INCONSISTENT = "RECOVERY_INCONSISTENT"
    CHECKPOINT_BAD = "CHECKPOINT_BAD"
    RUN_ORPHAN = "RUN_ORPHAN"
    RUN_UNSAVED = "RUN_UNSAVED"
    EVENT_AFTER_SUBMIT = "EVENT_AFTER_SUBMIT"
    EVENT_AFTER_END = "EVENT_AFTER_END"
    RECOVERED = "RECOVERED"
    RUN_OPEN = "RUN_OPEN"
    # clock
    CLOCK_BACKWARD = "CLOCK_BACKWARD"
    BOOT_REVISIT = "BOOT_REVISIT"
    CLOCK_STEP = "CLOCK_STEP"
    CLOCK_OFFSET = "CLOCK_OFFSET"
    CLOCK_DRIFT = "CLOCK_DRIFT"
    SILENCE = "SILENCE"
    # anchors
    ANCHOR_CONFLICT = "ANCHOR_CONFLICT"
    ROLLBACK = "ROLLBACK"
    TRUNCATED = "TRUNCATED"
    # submission
    SUBMISSION_MISMATCH = "SUBMISSION_MISMATCH"
    BLOB_MISSING = "BLOB_MISSING"
    MANIFEST_MISSING = "MANIFEST_MISSING"
    SUBMISSION_GAP = "SUBMISSION_GAP"


SUSPECT_CODES = frozenset({
    Code.BATCH_DEFECT, Code.UNKNOWN_SEAT, Code.KEY_NOT_ENROLLED, Code.DUPLICATE_KEY,
    Code.TRANSFER_INVALID, Code.TRANSFER_MISMATCH, Code.FORK, Code.MISSING_RANGE,
    Code.LINK_BREAK, Code.BAD_START, Code.ROSTER_MISMATCH, Code.PAPER_MISMATCH,
    Code.BOOT_UNMARKED, Code.RECOVERY_INCONSISTENT, Code.CHECKPOINT_BAD,
    Code.RUN_ORPHAN, Code.RUN_UNSAVED, Code.EVENT_AFTER_SUBMIT, Code.EVENT_AFTER_END,
    Code.CLOCK_BACKWARD, Code.BOOT_REVISIT, Code.ANCHOR_CONFLICT, Code.ROLLBACK,
    Code.TRUNCATED, Code.SUBMISSION_MISMATCH, Code.BLOB_MISSING,
})

# code -> (what it means, what a human should do)
MEANING: dict[Code, tuple[str, str]] = {
    Code.MALFORMED: ("A file could not be read as a batch. It was not used and belongs to no session.", "Check the transfer. Import the original again if it exists."),
    Code.BAD_SIGNATURE: ("A batch whose signature does not verify. It was not used.", "Compare with the copy in the workstation outbox."),
    Code.SIGNER_MISMATCH: ("A batch is signed by a key other than the one expected.", "Compare with the roster."),
    Code.WRONG_CONTEXT: ("An event names a different exam, session or seat than its batch header.", "Treat the batch as unusable and get the original."),
    Code.POLICY_VIOLATION: ("An event type or field outside the allow-list. Immutable never records keystrokes, screens or cameras.", "Find out which software wrote it."),
    Code.SEQ_GAP: ("Event numbers inside one batch are not consecutive.", "Get the original batch."),
    Code.CHAIN_BREAK: ("Inside one batch an event does not continue from the one before it.", "Get the original batch."),
    Code.HEADER_MISMATCH: ("A batch header disagrees with its own events.", "Get the original batch."),
    Code.WRONG_EXAM: ("Input from a different exam. It was not used.", "Check that the right bundle was imported."),
    Code.FOREIGN_BATCH: ("Input claiming a seat, signed by a key that is not enrolled for it. It was ignored.", "Informational. Look at it only if the seat's own log is also missing."),
    Code.BATCH_DEFECT: ("A batch signed by this seat's key is internally inconsistent and was not used.", "Ask for the workstation's original outbox and compare."),
    Code.ANCHOR_INVALID: ("An outside-holder record that failed its checks. It was not used.", "Check where it came from."),
    Code.UNKNOWN_SEAT: ("Evidence from a seat that is not on the roster or in any valid transfer.", "Find out which machine this was and why it was used."),
    Code.KEY_NOT_ENROLLED: ("Evidence for a seat signed by a key that is not enrolled for it, and no log from the enrolled key.", "Find out whether the student used a different machine."),
    Code.DUPLICATE_KEY: ("One key appears on more than one seat. This is typical of cloned disk images.", "Check how the machines were prepared."),
    Code.TRANSFER_INVALID: ("A seat transfer the assessor did not authorise for this seat and key.", "Check the transfer records with the exam office."),
    Code.TRANSFER_MISMATCH: ("The old seat's log does not end where the assessor recorded it.", "Compare the old machine's log with the assessor's record."),
    Code.FORK: ("Two different events were signed for the same position. The log cannot be trusted past this point.", "Compare both versions and the workstation's disk."),
    Code.MISSING_RANGE: ("Later events refer to events that were not provided.", "Look for the missing batches. A lost file and a removed file look the same."),
    Code.LINK_BREAK: ("Events exist here but do not continue the chain before them.", "Look for edited or removed events before this point."),
    Code.BAD_START: ("The log does not open the way an unmodified agent opens it.", "Check which software wrote it."),
    Code.ROSTER_MISMATCH: ("The session is not tied to the roster issued for this exam.", "Check which roster the machine was given."),
    Code.PAPER_MISMATCH: ("The exam paper on the machine is not the one the roster was issued for.", "Check which paper file was loaded."),
    Code.BOOT_UNMARKED: ("The machine changed boot without a recovery record, which a normal restart always leaves.", "Look for spliced or edited events."),
    Code.RECOVERY_INCONSISTENT: ("A recovery record disagrees with its position in the log.", "Compare with outside records."),
    Code.CHECKPOINT_BAD: ("A checkpoint does not match the events it claims to cover.", "Look for edited events before it."),
    Code.RUN_ORPHAN: ("A program run ended that never started.", "Look for removed events."),
    Code.RUN_UNSAVED: ("A program run used file contents that have no recorded save.", "Look for removed or edited save events."),
    Code.EVENT_AFTER_SUBMIT: ("Work was recorded after the submission.", "Find out what happened after submit."),
    Code.EVENT_AFTER_END: ("Events appear after the session ended.", "Find out what wrote them."),
    Code.RECOVERED: ("The agent restarted. Work was saved. Unacknowledged data from the interruption was dropped.", "Normal after a power cut or crash."),
    Code.RUN_OPEN: ("A program run has no recorded end, usually because the machine restarted.", "Normal after a crash."),
    Code.CLOCK_BACKWARD: ("The machine's uptime clock went backwards within one boot, which cannot happen.", "Look for edited events."),
    Code.BOOT_REVISIT: ("A boot identifier returned after a different boot.", "Look for spliced events."),
    Code.CLOCK_STEP: ("The wall clock jumped relative to the machine's uptime clock.", "Usually a clock sync. Read wall times in this stretch with care."),
    Code.CLOCK_OFFSET: ("The machine's clock differs from an outside holder's clock.", "Usually a dead clock battery. Use the outside holder's times."),
    Code.CLOCK_DRIFT: ("The wall clock ran fast or slow against the machine's uptime clock for a long stretch.", "Usually a clock sync or a failing clock. Read wall times in this stretch with care."),
    Code.SILENCE: ("A long stretch with no events.", "May be a student thinking, or the agent being stopped."),
    Code.ANCHOR_CONFLICT: ("An outside holder has a different event at this position than the log does.", "One of the two histories was rewritten."),
    Code.ROLLBACK: ("An outside holder saw events that a restart later removed from the log.", "Acknowledged history is missing. Ask about the restart."),
    Code.TRUNCATED: ("An outside holder saw events beyond the end of the log provided.", "Ask for the rest of the log."),
    Code.SUBMISSION_MISMATCH: ("The submitted files disagree with what was recorded while working.", "Compare the manifest with the recorded saves."),
    Code.BLOB_MISSING: ("A submitted file's contents are not in the evidence store.", "Import the submission folder."),
    Code.MANIFEST_MISSING: ("A submission was recorded but its manifest was not provided, so the files were not checked.", "Import the submission folder."),
    Code.SUBMISSION_GAP: ("A file saved during the session is not in the submission.", "It may have been deleted or moved. Ask the student."),
}


@dataclass(frozen=True)
class Finding:
    code: Code
    seq: int | None
    detail: str
    session: str | None = None
    ws: str | None = None

    @property
    def severity(self) -> Severity:
        return Severity.SUSPECT if self.code in SUSPECT_CODES else Severity.NOTE

    @property
    def sort_key(self) -> tuple:
        return (self.session or "", self.ws or "", -1 if self.seq is None else self.seq,
                self.code.value, self.detail)

    def to_dict(self) -> dict:
        return {"code": self.code.value, "severity": self.severity.value, "seq": self.seq,
                "session": self.session, "ws": self.ws, "detail": self.detail}

    def __str__(self) -> str:
        where = f" at seq {self.seq}" if self.seq is not None else ""
        return f"{self.code.value}{where}: {self.detail}"
