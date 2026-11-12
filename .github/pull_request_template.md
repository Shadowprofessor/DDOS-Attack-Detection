## What and why

<!-- One topic per PR. Link the issue if there is one. -->

## How it was tested

- [ ] `pytest tests/ -q` passes (paste the last line)
- [ ] Web app changes: lint, typecheck, unit tests, build, Playwright pass
- [ ] Results files changed → ran `python scripts/readme_results.py`

## Safety checklist

- [ ] No new path from a model/LLM decision to enforcement; every block still goes through `PendingActionManager.approve()` (`tests/test_mitigation_bypass.py` green)
- [ ] The LLM stays out of the packet fast path
- [ ] No traffic-generation code, or it was agreed in an issue first and stays inside the Mininet lab scope
- [ ] No secrets, keys or webhook URLs committed
- [ ] Any numbers are measured, with dev and held-out kept separate
- [ ] `CHANGELOG.md` updated under "Unreleased"
