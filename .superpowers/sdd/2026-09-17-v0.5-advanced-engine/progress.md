# SDD ledger — plan: docs/superpowers/plans/2026-09-17-v0.5-advanced-engine.md

## Pre-flight plan/interface scan

| Item | Shared file/interface | Result |
|---|---|---|
| Task 1 ↔ Task 4 | `core/models.py` evidence + module results | Compatible; deduplication must preserve finding evidence references. |
| Task 1 ↔ Task 5 | `core/models.py` session serialization feeds reports | Compatible; reports consume sanitized session data. |
| Task 2 ↔ Task 7 | `core/engine.py` registry integration | Compatible; CI exercises default registry. |
| Task 3 ↔ Task 4 | `PublicHTML` feeds auth/security analysis | Compatible; no automatic link requests/submissions. |
| Task 3 ↔ Task 6 | link/form metadata exposed through scan output | Compatible; CLI does not trigger extracted-link fetching. |
| Task 4 ↔ Task 5 | findings/evidence consumed by Markdown report | Compatible. |
| Task 5 ↔ Task 7 | report APIs consumed by integration/CI | Compatible; JSON remains additive/backward-compatible. |
| Task 6 ↔ Task 7 | safe policy and workflow inputs | Compatible; workflow remains bounded and observation-only. |

| Task | Internal consistency | Result |
|---|---|---|
| 1 | Testable helpers and model sanitization | OK |
| 2 | TLS module consumes existing network context and is registered explicitly | OK |
| 3 | HTML parsing stays within bounded response | OK |
| 4 | Findings are descriptive and evidence-backed | OK |
| 5 | Markdown renders the same `ScanSession` as JSON | OK |
| 6 | Safe profile exposes no offensive controls | OK |
| 7 | CI verifies v0.5 integration | OK |

## Rulings

Ruling: `feature/v0.5-advanced-engine` is anchored at verified v0.4 commit `754eedf24a3e2b6a738085660fedb45dffe677ba` — earlier branch creation accidentally pointed at an older base, so the ref was corrected before implementation.

Ruling: No subagent execution runtime is exposed in this session — execute the same SDD sequence inline with RED/GREEN/review gates rather than pretend an independent agent was dispatched.

## Task status

- Task 1: pending
- Task 2: pending
- Task 3: pending
- Task 4: pending
- Task 5: pending
- Task 6: pending
- Task 7: pending
- Final verification: pending
