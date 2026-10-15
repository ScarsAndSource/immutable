from immutable.sync import SyncController, SyncLocked, SyncState


class Clock:
    def __init__(self): self.value = 0.0
    def __call__(self): return self.value
    def advance(self, seconds): self.value += seconds


def make_controller(outcomes, clock):
    calls = {"flush": 0, "pump": 0}
    local = {"sealed_upto": 7}
    def flush(): calls["flush"] += 1
    def status(): return local
    def pump():
        calls["pump"] += 1
        result = outcomes.pop(0)
        if isinstance(result, Exception): raise result
        return result
    return SyncController(flush=flush, status=status, pump=pump, now=clock), calls


def ack(seq=7): return {"delivered_upto": seq, "pending": 0, "rejected": {}}


def down(): return {"delivered_upto": -1, "pending": 1, "rejected": {}, "last_error": "offline"}


def test_first_failure_gets_one_immediate_retry_without_locking():
    clock = Clock()
    sync, calls = make_controller([down(), ack()], clock)
    assert sync.synchronize()
    assert sync.snapshot().state is SyncState.SYNCED
    assert calls == {"flush": 2, "pump": 2}
    sync.require_editable()


def test_two_failed_attempts_lock_and_back_off_until_acknowledged():
    clock = Clock()
    sync, calls = make_controller([down(), down(), down(), ack()], clock)
    assert not sync.synchronize()
    before = sync.snapshot()
    assert before.state is SyncState.LOCKED and before.next_retry_in_ms == 1000
    try:
        sync.require_editable()
        assert False, "locked editor accepted an edit"
    except SyncLocked:
        pass
    assert not sync.tick()                 # retry is not busy-looped
    clock.advance(1)
    assert not sync.tick()
    assert sync.snapshot().next_retry_in_ms == 2000
    clock.advance(2)
    assert sync.tick()
    assert sync.snapshot().state is SyncState.SYNCED
    assert calls == {"flush": 4, "pump": 4}


def test_local_queue_is_not_mistaken_for_an_acknowledgement():
    clock = Clock()
    sync, _ = make_controller([{ "delivered_upto": 6, "pending": 0, "rejected": {} }, down()], clock)
    assert not sync.synchronize()
    assert sync.snapshot().state is SyncState.LOCKED


def test_permanent_rejection_locks_with_actionable_detail():
    clock = Clock()
    sync, _ = make_controller([{ "delivered_upto": -1, "pending": 0, "rejected": {"00000000-00000007.batch.json": "409 FORK"} },
                               { "delivered_upto": -1, "pending": 0, "rejected": {"00000000-00000007.batch.json": "409 FORK"} }], clock)
    assert not sync.synchronize()
    s = sync.snapshot()
    assert s.state is SyncState.LOCKED and "invigilator" in s.detail
