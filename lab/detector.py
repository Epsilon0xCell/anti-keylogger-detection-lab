"""Behavioural anti-keylogger detector, with quarantine.

Three tiers, and the honest idea behind them: signatures catch the
careless, behaviour catches the rest, and no tier catches
everything, a claim this repo makes about itself in the README
because it is true of every real product too.

- signature tier: the artifact's known fixture format or name.
- heuristic tier: artifact properties alone (steady small-append
  growth pattern recorded in telemetry, log-like file in an
  artifacts folder, encoded content with append telemetry).
- behavioural tier: the correlation that actually convicts:
  hook-install pattern AND periodic log appends AND a beacon
  reporting the artifact's size, from the same actor, in one run.

Quarantine is the lab's "removal": an artifact inside the sandbox
is moved to sandbox/quarantine with a receipt. Nothing outside the
sandbox can be quarantined, by path check, in code.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from .telemetry import Event, TelemetryLog

FIXTURE_HEADER = "LAB-SYNTHETIC-KEYLOG-FIXTURE"


def _actor_events(events: list[Event], actor: str) -> list[Event]:
    return [e for e in events if e.actor == actor]


def analyse(events: list[Event], sandbox: Path) -> dict:
    actors = sorted({e.actor for e in events})
    verdicts = []
    for actor in actors:
        evs = _actor_events(events, actor)
        types = [e.event_type for e in evs]
        hook = "hook_install_fixture" in types
        appends = [e for e in evs if e.event_type == "log_append"]
        beacon = any(e.event_type == "beacon" for e in evs)
        files = sorted({e.details.get("file") for e in evs
                        if e.details.get("file")})
        signature = False
        for name in files:
            p = sandbox / "artifacts" / name
            if p.is_file() and FIXTURE_HEADER in p.read_text(errors="ignore"):
                signature = True
        heuristic = len(appends) >= 3
        behavioural = bool(hook and len(appends) >= 3 and beacon)
        flagged = behavioural or signature
        verdicts.append({
            "actor": actor, "hook_pattern": hook,
            "append_count": len(appends), "beacon": beacon,
            "files": files, "signature_tier": signature,
            "heuristic_tier": heuristic, "behavioural_tier": behavioural,
            "flagged": flagged,
            "reason": ("hook pattern plus periodic appends plus size beacon "
                       "from one actor (T1056.001 behaviour chain)"
                       if behavioural else
                       "known fixture signature" if signature else
                       "behaviour chain incomplete, not flagged")})
    return {"verdicts": verdicts,
            "flagged_actors": [v["actor"] for v in verdicts if v["flagged"]]}


def quarantine(sandbox: Path, filename: str, log: TelemetryLog) -> Path:
    src = (sandbox / "artifacts" / filename).resolve()
    root = (sandbox / "artifacts").resolve()
    if root not in src.parents or not src.is_file():
        raise ValueError(f"refused: {filename} is not a lab artifact in the sandbox")
    qdir = sandbox / "quarantine"
    qdir.mkdir(parents=True, exist_ok=True)
    dest = qdir / filename
    shutil.move(str(src), str(dest))
    receipt = {"file": filename, "from": str(src), "to": str(dest),
               "action": "quarantined (lab removal)"}
    (qdir / f"{filename}.receipt.json").write_text(json.dumps(receipt, indent=2))
    log.emit("quarantine", "detector", **receipt)
    return dest
