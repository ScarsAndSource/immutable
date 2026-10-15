import tempfile
from pathlib import Path

from immutable import canon, final_receipt, hashing, keys
from immutable.batch import seal
from immutable.events import ChainWriter
from immutable.roster import Roster, Seat, Server
from immutable.store import Store


def roster_pair():
    assessor, seat, server = keys.Signer.generate(), keys.Signer.generate(), keys.Signer.generate()
    common = dict(exam_id="EX1", paper_sha256="a" * 64,
                  seats=[Seat("WS1", seat.pub_hex, "C1")], issued_ms=1)
    return (Roster.build(assessor, **common), Roster.build(assessor, **common,
            servers=[Server("srv1", server.pub_hex)]), seat, server)


def test_v1_roster_stays_v1_and_v2_adds_only_server_lookup():
    v1, v2, _, _ = roster_pair()
    assert v1.body["v"] == 1 and not v1.servers
    assert v2.body["v"] == 2 and v2.server("srv1") is not None


def test_imr2_validates_server_signature_and_roster_binding():
    _, roster, _, server = roster_pair()
    body = {"v": 2, "kind": "final", "exam_id": "EX1", "session_id": "S1", "ws_id": "WS1",
            "candidate": "C1", "final_seq": 2, "head": "b" * 64, "manifest_sha256": "c" * 64,
            "file_count": 0, "submit_seq": None, "reason": "window_end", "finalized_ms": 2,
            "last_confirmed_ms": 2, "outage_count": 0, "outage_total_ms": 0, "journal_head": "d" * 64,
            "roster_sha256": roster.id, "schedule_sha256": "e" * 64, "paper_sha256": "a" * 64,
            "server_id": "srv1"}
    raw = canon.dumps({"body": body, "sig": server.sign(hashing.FINAL, canon.dumps(body))})
    assert final_receipt.validate(final_receipt.encode(raw), roster).valid


def test_export_adapter_uses_existing_store_ingestion_without_verifier_changes():
    _, roster, seat, _ = roster_pair()
    writer = ChainWriter("EX1", "S1", "WS1", boot_id="boot")
    event = writer.append("BOOT", {"reason": "start"}, wall_ms=1, boot_ns=1)
    raw_batch = seal(seat, [event]).to_bytes()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "batches").mkdir()
        (root / "batches" / "one.batch.json").write_bytes(raw_batch)
        store = Store(root / "store", roster)
        try:
            result = store.ingest_v2_export(root)
            assert result["batch:stored"] == 1
        finally:
            store.close()
