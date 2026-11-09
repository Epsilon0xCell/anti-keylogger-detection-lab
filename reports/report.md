# Anti-keylogger detection report (auto-generated)

Flagged actors: ['keylogger_sim']

| Actor | Hook pattern | Appends | Beacon | Signature | Heuristic | Behavioural | Flagged |
|---|---|---|---|---|---|---|---|
| keylogger_sim | True | 24 | True | True | True | True | True |
| text_editor | False | 0 | False | False | False | False | False |

Quarantined lab artifacts: ['cache_data.bin', 'input_log.txt', 'session_notes.txt']

The benign editor fixture is scored as its own actor and must never be flagged; the tests enforce that.
