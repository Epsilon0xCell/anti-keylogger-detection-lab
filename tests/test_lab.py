from pathlib import Path

import pytest

from lab import detector, keylogger_sim
from lab.telemetry import TelemetryLog


@pytest.fixture()
def sandbox(tmp_path):
    return tmp_path / "sandbox"


def _run_variants(sandbox):
    log = TelemetryLog()
    for variant in ("basic", "renamed", "encoded", "slow"):
        keylogger_sim.run_simulation(sandbox, log, variant=variant)
    keylogger_sim.benign_editor_fixture(sandbox, log)
    return log


def test_unknown_variant_is_refused(sandbox):
    log = TelemetryLog()
    with pytest.raises(ValueError):
        keylogger_sim.run_simulation(sandbox, log, variant="encodde")


def test_simulator_captures_nothing_by_construction():
    import inspect
    src = inspect.getsource(keylogger_sim)
    for banned in ("keyboard", "pynput", "GetAsyncKeyState", "SetWindowsHookEx",
                   "ctypes", "subprocess", "socket"):
        assert banned not in src, banned


def test_detector_flags_sim_and_spares_benign(sandbox):
    log = _run_variants(sandbox)
    analysis = detector.analyse(log.events, sandbox)
    assert analysis["flagged_actors"] == ["keylogger_sim"]
    benign = [v for v in analysis["verdicts"] if v["actor"] == "text_editor"][0]
    assert benign["flagged"] is False


def test_behavioural_tier_is_the_conviction(sandbox):
    log = _run_variants(sandbox)
    v = [x for x in detector.analyse(log.events, sandbox)["verdicts"]
         if x["actor"] == "keylogger_sim"][0]
    assert v["behavioural_tier"] is True and v["hook_pattern"] is True
    assert v["append_count"] >= 12 and v["beacon"] is True


def test_quarantine_removes_lab_artifact_and_refuses_outside(sandbox):
    log = TelemetryLog()
    art = keylogger_sim.run_simulation(sandbox, log, variant="basic")
    dest = detector.quarantine(sandbox, art.name, log)
    assert dest.is_file() and not art.exists()
    assert (sandbox / "quarantine" / f"{art.name}.receipt.json").is_file()
    with pytest.raises(ValueError):
        detector.quarantine(sandbox, "../outside.txt", log)
