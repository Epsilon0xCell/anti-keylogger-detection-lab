"""One-command exercise: simulate the variants, detect, quarantine, report.

    python -m lab.run_lab
"""
from __future__ import annotations

import json
from pathlib import Path

from . import detector, keylogger_sim
from .telemetry import TelemetryLog

ROOT = Path(__file__).resolve().parent.parent
SANDBOX = ROOT / "sandbox"


def main() -> int:
    log_path = ROOT / "evidence" / "sample_run_log.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if log_path.exists():
        log_path.unlink()
    log = TelemetryLog(log_path)
    for variant in ("basic", "renamed", "encoded", "slow"):
        keylogger_sim.run_simulation(SANDBOX, log, variant=variant)
    keylogger_sim.benign_editor_fixture(SANDBOX, log)
    analysis = detector.analyse(log.events, SANDBOX)
    quarantined = []
    for verdict in analysis["verdicts"]:
        if verdict["flagged"]:
            for name in verdict["files"]:
                if (SANDBOX / "artifacts" / name).is_file():
                    detector.quarantine(SANDBOX, name, log)
                    quarantined.append(name)
    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "analysis.json").write_text(json.dumps(analysis, indent=2))
    lines = ["# Anti-keylogger detection report (auto-generated)", "",
             f"Flagged actors: {analysis['flagged_actors']}", "",
             "| Actor | Hook pattern | Appends | Beacon | Signature | Heuristic | Behavioural | Flagged |",
             "|---|---|---|---|---|---|---|---|"]
    for v in analysis["verdicts"]:
        lines.append(f"| {v['actor']} | {v['hook_pattern']} | {v['append_count']} | "
                     f"{v['beacon']} | {v['signature_tier']} | {v['heuristic_tier']} | "
                     f"{v['behavioural_tier']} | {v['flagged']} |")
    lines += ["", f"Quarantined lab artifacts: {sorted(quarantined)}",
              "", "The benign editor fixture is scored as its own actor and "
              "must never be flagged; the tests enforce that."]
    (reports / "report.md").write_text("\n".join(lines) + "\n")
    print(f"flagged actors: {analysis['flagged_actors']}")
    print(f"quarantined: {sorted(quarantined)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
