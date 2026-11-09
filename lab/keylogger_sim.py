"""Keylogger-BEHAVIOUR simulator. Captures no input, ever.

Real keyloggers (mechanism lesson in docs/keylogger_mechanisms.md,
describe-only) obtain keystrokes through OS hooks, polling, or
kernel filters, write them to a log, and periodically send the log
out. Every one of those steps leaves observables. This simulator
reproduces ONLY the observables, as fixtures:

- a synthetic "hook installed" telemetry event (data describing the
  pattern a detector looks for; no hook is created);
- a dummy log artifact in the sandbox, appended in small periodic
  chunks whose content is invented by the simulator from a word
  list (it is not, and cannot be, anything anyone typed);
- periodic beacon events carrying a byte COUNT only, to a log, the
  same shape an exfiltration beacon would take in telemetry.

Variants model what detectors must survive: renamed artifact,
encoded artifact content, slow cadence. Each variant is a file and
telemetry pattern in the sandbox, not a technique applied to any
real system, and nothing here hides from the lab's own logging.
"""
from __future__ import annotations

import base64
import random
from pathlib import Path

from .telemetry import TelemetryLog

WORDS = ("lab", "dummy", "synthetic", "fixture", "telemetry",
         "detection", "sandbox", "example", "placeholder", "sample")
ACTOR = "keylogger_sim"


def _synthetic_chunk(rng: random.Random, n: int = 24) -> str:
    return " ".join(rng.choice(WORDS) for _ in range(n))


def run_simulation(sandbox: Path, log: TelemetryLog, variant: str = "basic",
                   appends: int = 6, seed: int = 42) -> Path:
    """Create one dummy artifact plus its telemetry. Returns the artifact."""
    rng = random.Random(seed)
    art_dir = sandbox / "artifacts"
    art_dir.mkdir(parents=True, exist_ok=True)
    log.emit("hook_install_fixture", ACTOR, synthetic=True,
             api_pattern="WH_KEYBOARD_LL (fixture description only)",
             scope="global", attck="T1056.001")
    if variant == "renamed":
        name = "cache_data.bin"
    elif variant == "encoded":
        name = "session_notes.txt"
    else:
        name = "input_log.txt"
    artifact = art_dir / name
    chunks = []
    for i in range(appends):
        chunk = _synthetic_chunk(rng)
        chunks.append(chunk)
        log.emit("log_append", ACTOR, file=name, bytes=len(chunk),
                 cadence_s=5 if variant != "slow" else 60)
    content = "\n".join(chunks)
    if variant == "encoded":
        artifact.write_bytes(base64.b64encode(content.encode()))
    else:
        artifact.write_text("LAB-SYNTHETIC-KEYLOG-FIXTURE\n" + content)
    log.emit("beacon", ACTOR, file=name, bytes_reported=artifact.stat().st_size,
             destination="lab://fake-c2 (simulated, no connection made)")
    return artifact


def benign_editor_fixture(sandbox: Path, log: TelemetryLog) -> Path:
    """A benign lookalike: user-initiated document saves, no hook events,
    no beacon. A detector that flags this is crying wolf, and the
    tests hold it to that."""
    doc_dir = sandbox / "documents"
    doc_dir.mkdir(parents=True, exist_ok=True)
    doc = doc_dir / "essay.txt"
    doc.write_text("A perfectly ordinary essay about detection engineering.\n"
                   "Saved twice by its author, on purpose.\n")
    log.emit("file_save", "text_editor", file="essay.txt", user_initiated=True)
    log.emit("file_save", "text_editor", file="essay.txt", user_initiated=True)
    return doc
