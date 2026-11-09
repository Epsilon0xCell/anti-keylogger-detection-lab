"""Minimal structured telemetry, same schema idea as the combined lab."""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Event:
    event_type: str
    actor: str
    ts: float = field(default_factory=time.time)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class TelemetryLog:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self.events: list[Event] = []
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, event_type: str, actor: str, **details: Any) -> Event:
        ev = Event(event_type=event_type, actor=actor, details=details)
        self.events.append(ev)
        if self.path is not None:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(ev.to_dict()) + "\n")
        return ev
