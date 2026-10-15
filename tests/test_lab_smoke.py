"""tests/test_lab_smoke.py: import guard and world-build smoke test.

These tests do NOT execute scenarios (that is what `tamper_lab.py run` does).
They just confirm that all modules import cleanly and the world can be built.
"""
import tempfile
from pathlib import Path


def test_import_scenarios() -> None:
    from lab.scenarios import SCENARIOS
    assert len(SCENARIOS) >= 30, f"expected >=30 scenarios, got {len(SCENARIOS)}"


def test_all_scenario_ids_unique() -> None:
    from lab.scenarios import SCENARIOS
    ids = [s.id for s in SCENARIOS]
    assert len(ids) == len(set(ids)), "duplicate scenario IDs"


def test_world_builds() -> None:
    from lab.world import World
    with tempfile.TemporaryDirectory() as tmp:
        w = World.build(tmp)
        assert len(w.seats) == 6
        assert len(w.spares) == 3
        assert w.roster is not None
        assert w.assessor is not None
        assert w.witness_signer is not None
        assert w.rogue is not None


def test_model_imports() -> None:
    from lab.model import Outcome, Expect, Inputs, Obs, Scenario, Inapplicable, E
    assert Outcome.DETECTED.value == "DETECTED"
    assert Outcome.MISSED.value == "MISSED"


def test_scenario_has_required_fields() -> None:
    from lab.scenarios import SCENARIOS
    for s in SCENARIOS:
        assert s.id, f"scenario missing id: {s}"
        assert s.title, f"scenario {s.id} missing title"
        assert s.expect is not None, f"scenario {s.id} missing expect"
        assert callable(s.build), f"scenario {s.id} build is not callable"


def test_ctx_importable() -> None:
    from lab.scenarios import Ctx
    import tempfile, random
    from lab.world import World
    with tempfile.TemporaryDirectory() as tmp:
        w = World.build(tmp, n_seats=2, n_spares=1)
        ctx = Ctx(w, random.Random(0), Path(tmp) / "ctx_test")
        assert ctx.world is w
