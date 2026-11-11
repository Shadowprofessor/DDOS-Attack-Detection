# Risk register (v5.0.0)

Likelihood (L) and impact (I) are scored 1–5; inherent risk = L × I. Residual risk is
re-scored after the listed treatment. Owner = the platform owner unless stated. Each risk points
to its evidence.

| ID | Risk | L | I | Inherent | Treatment | Residual (L×I) | Evidence |
|---|---|---:|---:|---:|---|---:|---|
| R1 | **ML misses real-world floods** (classifier does not transfer beyond CIC-DDoS2019; 0/1,452 lab SYN flows) | 4 | 4 | 16 | Defence in depth: L1 rules + rule-based L3 detected 3/6 fully and 3/6 partially in the lab. ML is not relied on alone. Next: retrain with lab/CICIoT2023 data | 3×3 = **9** | `docs/purple_team/README.md`, `docs/eval/cross_dataset.md` |
| R2 | **False positives on legitimate surges** (L1 fired on 41% of flash-crowd flows) | 4 | 3 | 12 | Humans approve every block; auto-rollback 10 min. Next: adaptive per-destination baselines | 3×2 = **6** | lab finding 2 |
| R3 | Automated block hits a legitimate customer | 2 | 4 | 8 | No auto-execution; approval needs an admin; blast radius shown; rollback TTL | 1×3 = **3** | `test_mitigation_bypass.py`, `test_ir.py::TestRollback` |
| R4 | LLM prompt injection via telemetry changes the recommendation | 3 | 3 | 9 | Sanitise + `<telemetry>` wrapping + code-enforced output policy; LLM cannot execute | 2×2 = **4** | `test_injection_policy.py`, injection eval (0/31) |
| R5 | API key leak gives an attacker analyst or admin access | 2 | 5 | 10 | Keys only in env; session hides the key; per-request role re-check; write/chat rate limits | 2×4 = **8** (shared keys, no MFA) | `test_soc_session.py`, `test_bug_hunt_fixes.py` |
| R6 | Malicious model artifact executes code on load (pickle) | 1 | 5 | 5 | Artifacts operator-written and gitignored. Planned: SHA-256 manifest check | 1×5 = **5** (accepted) | STRIDE T3 |
| R7 | Lab attack traffic escapes to a real network | 1 | 5 | 5 | Code-enforced scope, per-packet guard, netns check, kill switch, nftables egress drop | 1×3 = **3** | `test_lab_safety.py`, `test_lab_traffic.py`, containment 3/3 |
| R8 | CERT-In 6 h deadline missed | 2 | 4 | 8 | Timer + gauge + 1 h / 15 min / breach warnings; draft ready. Submission is human | 2×3 = **6** | `test_ir.py::TestCertIn` |
| R9 | Incident record tampering goes unnoticed | 2 | 3 | 6 | Hash-chained timeline verified on every view/export | 2×2 = **4** (head not anchored) | `test_ir.py::TestHashChain` |
| R10 | Vulnerable dependency shipped | 3 | 3 | 9 | Pinned deps, pip-audit / npm audit, Dependabot, CodeQL, SBOM per release | 2×2 = **4** | CI `security.yml`, `webapp.yml` |
| R11 | LLM provider outage or quota exhausted (observed: NIM timeouts and 503) | 4 | 2 | 8 | Timeout → deterministic rule fallback; one call per incident; chat rate limit | 4×1 = **4** | `test_threat_analyst.py`, CHANGELOG 4.7.0 |
| R12 | `/metrics` leaks incident counts and ids | 3 | 1 | 3 | Accepted: restrict at the proxy/network in production | **3** (accepted) | STRIDE I4 |
