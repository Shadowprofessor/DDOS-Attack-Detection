# Contributing

Thanks for looking. Issues and pull requests are welcome: bug reports, false positives or false
negatives you can reproduce, docs fixes and new tests.

## Ground rules (these are enforced by tests and review)

- **The AI recommends; it never executes.** No code path may run `iptables`, `nftables`, `tc`, `docker`
  or an OpenFlow DROP as a direct result of a model or LLM decision. Every block goes through
  `PendingActionManager.approve()` by an admin. `tests/test_mitigation_bypass.py` must stay green.
- **The LLM is never in the packet fast path.** It only sees aggregated, sanitised incidents.
- **Attack traffic is lab-only:** isolated Mininet, netns or containers that you own. Never a real target.
  Open an issue before proposing any new traffic-generation code.
- **No secrets in the repo.** Keys come from the environment or a gitignored `.env`.
- **Honest numbers.** Report what you measured, including misses. Never tune on held-out data. Keep
  dev and held-out results separate.
- Datasets only from [docs/DATASETS.md](docs/DATASETS.md), with citations.

The full development rules are in [AGENTS.md](AGENTS.md) and [PROJECT_RULES.md](PROJECT_RULES.md).

## Workflow

1. Fork `https://github.com/Shadowprofessor/DDOS-Attack-Detection`.
2. Create a branch: `git checkout -b feat/my-change`.
3. Make the change, with a test.
4. Run the checks below.
5. Open a pull request.

## Setup and checks

```bash
pip install -r requirements.txt
pytest tests/ -q                               # full suite, must pass
pytest tests/test_mitigation_bypass.py -v      # the approval gate cannot be bypassed (AST scan)
(cd dashboard && npm ci && npm run lint && npx tsc --noEmit && npm test && npm run build && npx playwright test)
python scripts/readme_results.py --check       # README/REPORT results match the results files
```

If you change any results file under `docs/eval/` or `docs/purple_team/`, run
`python scripts/readme_results.py` and commit the regenerated README and REPORT.

## Pull requests

- One topic per PR, on a feature branch, with a clear title (for example `fix: ...`, `feat: ...`, `docs: ...`).
- Every feature or fix ships with a test.
- Fill in the PR template, including the safety checklist.
- CI has to pass: tests, the web app, CodeQL with no new high or medium alerts, Bandit, gitleaks and
  the dependency audit.
- Update `CHANGELOG.md` under an "Unreleased" heading.

## Style

Match the existing code. Keep changes small, with no unrelated refactors. Never silence errors, disable
tests or loosen lint rules to make something pass.

By contributing you agree that your contribution is licensed under the repository's [LICENSE](LICENSE),
and you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
