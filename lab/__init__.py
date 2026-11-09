"""Anti-keylogger detection lab.

The simulator in this package captures NOTHING. It installs no hook,
reads no keyboard, and records no input. It generates synthetic
telemetry fixtures and dummy log artifacts that reproduce the
OBSERVABLES of keylogger behaviour (hook-install pattern, periodic
small appends to a log file, periodic beaconing of counts), so the
detector beside it can be built, measured and taught. The capture
techniques themselves are describe-only, in docs/.
"""
__version__ = "1.0.0"
