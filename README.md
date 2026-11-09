# Anti-Keylogger Detection Lab

EDUCATIONAL AND DEFENSIVE USE ONLY. Read DISCLAIMER.md and
RESPONSIBLE_USE.md before running anything. This is a template
disclaimer set, not legal advice.

A behavioural detector for keylogger-style behaviour (MITRE ATT&CK
T1056.001), a simulator that generates its observable patterns
without capturing any input, and the fixtures and tests that score
the detector honestly.

## The honest claim, up front

No antivirus detects and removes "any advanced keylogger", and
this lab does not either. Products that claim otherwise are
marketing, and repeating that claim in a portfolio would undermine
it. What this repo demonstrates is the real, hireable skill:
modelling a threat's behaviour chain (hook pattern, periodic log
appends, size-reporting beacon), building a tiered detector
(signature, heuristic, behavioural correlation), proving it
against variants and against a benign lookalike it must not flag,
quarantining what it catches inside the lab, and publishing the
coverage boundary in writing (docs/keylogger_mechanisms.md).

## What the simulator is, and is not

lab/keylogger_sim.py captures NOTHING. It installs no hook, reads
no keyboard, records no input, and contains no capture API. It
emits synthetic telemetry fixtures and dummy log artifacts whose
content it invents from a word list, reproducing only the
observables a detector sees: a hook-install pattern event, small
periodic appends, a beacon carrying a byte count. Variants cover a
renamed artifact, encoded artifact content, and slow cadence.
Stealth and evasion techniques are described in the docs for
detection purposes and are not implemented.

## Quick start

    pip install -e ".[dev]"
    python -m lab.run_lab
    pytest -q

The run writes reports/report.md and reports/analysis.json:
the simulator's actor flagged and its lab artifacts quarantined,
the benign editor actor unflagged.

## Layout

- lab/keylogger_sim.py: behaviour fixtures, zero input capture
- lab/detector.py: tiered analysis plus sandbox-only quarantine
- lab/telemetry.py: structured event schema and JSONL log
- lab/run_lab.py: one-command exercise and report generation
- docs/keylogger_mechanisms.md: capture classes, detection
  surfaces, and the stated coverage boundary
- tests/: including a test that the simulator's source contains
  no capture machinery at all
