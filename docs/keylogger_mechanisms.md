# Keylogger mechanisms, taught through their detection

ATT&CK: T1056.001 Input Capture, Keylogging. The capture techniques
below are described at the level of published research and vendor
documentation. They are the describe-only half of this lab; the
code half is the simulator's fixtures and the detector.

How real keyloggers obtain keystrokes, in classes:

1. User-mode API hooking. A global keyboard hook (the WH_KEYBOARD_LL
   pattern on Windows) receives key events before applications do.
   Detection surface: hook installation by a process with no UI
   reason to hold one, and the hook chain itself is enumerable.
2. State polling. Periodically querying key state for every virtual
   key at high frequency. Detection surface: the polling cadence
   and CPU/scan pattern, and a process with no visible window doing
   it continuously.
3. Kernel keyboard filters. A driver in the keyboard device stack
   sees scan codes below user mode. Detection surface: unexpected
   filter drivers in the stack, the same driver-audit problem as
   the rootkit and BYOVD material in the companion lab.
4. Form grabbing and web injects. Capturing data inside the browser
   instead of at the keyboard. Detection surface: browser process
   tampering and unexpected form-post destinations.

What every class still has to do, and where this detector lives:
write the captured material somewhere (periodic small appends to a
log artifact) and move it out (periodic transmission). Hook pattern
plus append cadence plus size-reporting beacon, from one actor, is
a behaviour chain no single step of which is damning and all of
which together are. That correlation, and its false-positive
discipline (a text editor saving a document must never flag), is
the professional skill this repo teaches.

An honest limitation, stated the way a real vendor should: a
keylogger that never writes a local log, or that rides a legitimate
process end to end, weakens two of the three chain links. This
detector, like every real product, has a coverage boundary. It is
drawn in the README rather than hidden, because that honesty is
what separates detection engineering from marketing.
