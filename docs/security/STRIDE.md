# STRIDE threat model (v4.7.0)

Scope: the platform as built through v4.6.1. Each threat lists the mitigation **in code**, the
test or CI check that holds it in place, and the residual risk. "Accepted" means a known gap
that is documented rather than fixed.

## Data flow

```
 traffic ──► L1 capture / sanity / signature / threshold / low-and-slow ──► L2 ensemble + OOD
                                                                              │
                                 aggregated incident (no raw packets) ◄───────┘
                                            │
                     L3 analyst (LLM or rules) ── recommendation only ──► IR store (SQLite, hash-chained timeline)
                                            │                                   │
                                 PendingActionManager.propose()  ◄── playbooks  │
                                            │                                   │
                       admin approve() ──► enforcers (OpenFlow / Cloudflare / logged commands)
                                            │                                   │
                         auto-rollback revert() ◄── scheduler                   ▼
                                                              SOC web app (/app) + REST + WebSockets
```

Trust boundaries: (1) network traffic, all attacker-controlled; (2) LLM output, untrusted;
(3) browser ↔ API; (4) the model artifacts on disk; (5) the lab ↔ the real network.

## Threats

| # | STRIDE | Element | Threat | Mitigation (code) | Evidence | Residual |
|---|---|---|---|---|---|---|
| S1 | Spoofing | API | Caller impersonates an analyst or admin | API keys from env only. Prod/staging refuse to start without keys. Session = opaque server-side id; role re-resolved per request, so revocation is immediate | `test_auth_hardening`, `test_soc_session::test_revoked_key_kills_session` | Keys are long-lived shared secrets; no per-user identity or MFA (accepted for a single-team SOC) |
| S2 | Spoofing | WebSockets | Another site rides the session cookie (CSWSH) | Cookie WS auth only for same-origin handshakes (`Origin` host == `Host`); SameSite=Strict | `test_soc_detail::TestWsCookieAuth`, `test_soc_pages::test_legacy_stream_rejects_cross_origin_cookie` | — |
| S3 | Spoofing | L1 | Spoofed source IPs evade per-source thresholds | Per-destination thresholds; L3 sees the aggregate. **H1 hunt rule** catches many low-rate reflectors | `test_hunt_rules::TestH1LowRateReflection` | Fixed thresholds also false-positive on flash crowds (v4.6.1 lab finding) |
| T1 | Tampering | IR timeline | Edit or delete incident history | SHA-256 hash chain; `verify_chain()` shown on every incident and export | `test_ir::TestHashChain` (5 tamper cases) | Tamper-*evident*, not tamper-proof; head hash not anchored externally |
| T2 | Tampering | Browser | CSRF on state changes | Synchroniser token on cookie-authenticated mutations; SameSite=Strict | `test_soc_session::TestCSRF`, Playwright CSRF test | — |
| T3 | Tampering | Model artifacts | A replaced `.pkl`/`.joblib` executes code on load (pickle) | Artifacts are gitignored, so only the operator writes them | — | **Accepted:** no hash pinning of artifacts yet (recommended: verify SHA-256 manifest before `joblib.load`) |
| T4 | Tampering | Dependencies | Malicious or vulnerable package | Pinned `requirements.txt` + `package-lock.json`, pip-audit, npm audit, Dependabot, CycloneDX SBOM | CI `security.yml`, `webapp.yml` | Transitive pins not hash-locked |
| R1 | Repudiation | Approvals | Admin denies approving a block | Approver recorded on the action; every transition / extend / rollback is a hash-chained event with the actor's key fingerprint | `test_ir`, `test_ir_api` | Fingerprint identifies a key, not a person |
| I1 | Info disclosure | Logs | Attacker-controlled strings forge log lines | `log_safe()` escapes CR/LF on all untrusted values | `test_codeql_hardening` | — |
| I2 | Info disclosure | UI / exports | Stored XSS / markdown injection via telemetry or LLM text | React text rendering only (ESLint bans raw HTML), strict CSP, MD/PDF escaping | Playwright XSS test, `test_ir::TestExport` | — |
| I3 | Info disclosure | Keys | Key leaks to the browser or logs | Key exchanged for an HttpOnly session and never returned; dev keys written to an owner-only file; `/api/system` shows only "key present" | `test_soc_session::test_cookie_flags`, `test_soc_pages::test_system_info_has_no_secrets` | — |
| I4 | Info disclosure | `/metrics` | Unauthenticated scrape reveals incident counts and incident ids (CERT-In gauge label) | — | — | **Accepted:** put `/metrics` behind the network / reverse-proxy auth in production |
| I5 | Info disclosure | LLM | Telemetry exfiltrated via prompt injection | Telemetry sanitised and wrapped in `<telemetry>`; output policy; optional IP pseudonymisation | `test_injection_policy`, injection eval (0/31 with defences) | Static payloads only; adaptive attacks untested |
| D1 | DoS | API | Authenticated flooding of write endpoints / LLM chat (cost) | Login, scoring and analyst rate limits; **v4.7.0 adds per-actor limits on IR writes and `/api/chat`** | `test_bug_hunt_fixes` | In-memory limiters reset on restart and are per process |
| D2 | DoS | Analyst | LLM latency stalls detection | LLM never in the fast path; one call per incident; timeout → rules | `test_threat_analyst`, `test_nemotron_agent` | — |
| E1 | Elevation | Mitigation | Model/LLM/playbook triggers a block without a human | Everything goes through `PendingActionManager.propose()`; only `approve_action_endpoint` calls `approve()`; IR code may only `revert()` | `test_mitigation_bypass` (AST), `test_ir::TestNoDirectEnforcement` | — |
| E2 | Elevation | RBAC | Analyst performs admin actions | Deny-by-default roles; matrix test of every endpoint × role | `test_ir_api::TestRBACMatrix`, Playwright analyst-approve → 403 | — |
| E3 | Elevation | Lab | Lab traffic escapes to a real target | Code-enforced scope, per-packet guard, kill switch, WSL2+Mininet netns check, nftables egress drop | `test_lab_safety`, `test_lab_traffic`, measured containment (3/3 dropped) | Containment proven for ICMP only; other protocols rely on the same rule |
