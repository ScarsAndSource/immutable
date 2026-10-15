import tempfile
from pathlib import Path

from immutable import receipt as R
from immutable.server import ImmutableService


def _submitted(tmp):
    s = ImmutableService(root_dir=Path(tmp))
    s.save_file("a.py", "print(1)")
    s.flush()
    return s, s.submit()


def test_receipt_round_trip_and_offline_valid():
    with tempfile.TemporaryDirectory() as tmp:
        s, rc = _submitted(tmp)
        try:
            assert R.encode(R.decode(rc["token"])) == rc["token"]
            assert R.validate(rc["token"], s.roster).valid
        finally:
            s.close()


def test_valid_against_evidence_and_not_forgeable_by_edit():
    with tempfile.TemporaryDirectory() as tmp:
        s, rc = _submitted(tmp)
        try:
            res = R.validate(rc["token"], s.roster, evidence=[s.evidence_dir])
            codes = {c.code: c.ok for c in res.checks}
            assert res.valid and codes["R_ON_LOG"] and codes["R_FINAL"]

            t = rc["token"]
            i = 60
            bad = t[:i] + ("A" if t[i] != "A" else "B") + t[i + 1:]
            assert not R.validate(bad, s.roster).valid

            # right seat key, wrong head: a root user rewriting history
            forged = R.encode(R.issue(
                s.ws_signer, exam_id=s.exam_id, session_id=s.session_id, ws_id=s.ws_id,
                last_seq=rc["last_seq"], head="a" * 64))
            f = R.validate(forged, s.roster, evidence=[s.evidence_dir])
            assert {c.code: c.ok for c in f.checks}["R_SIGNATURE"]
            assert not {c.code: c.ok for c in f.checks}["R_ON_LOG"]
            assert not f.valid
        finally:
            s.close()


def test_wrong_key_fails_signature():
    from immutable import keys
    with tempfile.TemporaryDirectory() as tmp:
        s, rc = _submitted(tmp)
        try:
            other = R.encode(R.issue(
                keys.Signer.generate(), exam_id=s.exam_id, session_id=s.session_id,
                ws_id=s.ws_id, last_seq=rc["last_seq"], head=rc["head"]))
            assert not {c.code: c.ok for c in R.validate(other, s.roster).checks}["R_SIGNATURE"]
        finally:
            s.close()
