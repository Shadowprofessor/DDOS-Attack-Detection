# Bug hunt (v4.7.0)

A manual review of the API, the SOC web app and the enforcers. It followed the roadmap
checklist: authz/IDOR, CSRF, SSRF, injection, deserialisation, rate limits, plus anything else
found along the way. Each item is **fixed** (with a regression test), **by design** (with the
reason), or **accepted** (risk documented in `STRIDE.md`).

| # | Area | Finding | Severity | Status | Evidence |
|---|---|---|---|---|---|
| B1 | Rate limits | IR write endpoints (`POST /api/incidents`, notes, actions, playbook steps, transitions, analyse, replay) had **no rate limit**, so a leaked analyst key could flood the incident DB and timeline. | Medium | **Fixed:** per-actor limit, `DDOS_IR_WRITE_RATE_PER_MIN` (default 120); reads stay unlimited | `test_bug_hunt_fixes::test_ir_writes_are_rate_limited_per_actor`, `test_replay_shares_the_write_limit` |
| B2 | Rate limits / cost | `POST /api/chat` calls the LLM per message with **no limit** (unbounded cost, and the shared NIM quota can be exhausted). | Medium | **Fixed:** per-key limit, `DDOS_CHAT_RATE_PER_MIN` (default 20) | `test_chat_is_rate_limited` |
| B3 | Input handling | `/api/chat` raised an **unhandled 500** when the JSON body was not an object (`[]`, `"x"`, `42`). Messages were unbounded. | Low | **Fixed:** non-object bodies treated as empty; message capped at 2,000 chars | `test_chat_non_object_body_is_not_a_500`, `test_chat_message_is_truncated` |
| B4 | Product logic | `family_from_text()` matched "ood" inside "flood", so UDP-flood incidents got the **zero-day playbook** (found by the v4.6.1 lab run). | Medium | **Fixed in v4.6.1** (whole-word match) | `test_ir::TestLifecycle::test_family_mapping` |
| B5 | Detection logic | The low-and-slow rule counts half-open SYN-flood flows to 80/443 as "slow connections", so L3 called the lab SYN flood Slowloris (v4.6.1). | Medium | **Open** (recommended: only count connections with a completed handshake) | `docs/purple_team/README.md` finding 3 |
| B6 | Authz / IDOR | Any analyst can read any incident by id. | — | **By design:** single-tenant SOC, so all analysts share the incident queue. Admin-only actions are enforced per endpoint (RBAC matrix). | `test_ir_api::TestRBACMatrix` |
| B7 | CSRF | Cookie-authenticated mutations require the synchroniser token; header-key clients are not cookie-bound. | — | Verified, no issue | `test_soc_session::TestCSRF`, Playwright |
| B8 | SSRF | Enforcer URLs: Cloudflare uses the fixed `https://api.cloudflare.com/...` host, and the account id comes from admin config, not requests. The LLM `base_url` comes from config/env only. | — | Verified, no issue | `src/mitigation/cloud_enforcers/cloudflare.py` |
| B9 | Injection | DB access is ORM-only (no string SQL). MD/PDF exports escape untrusted text. Orchestrator commands use argument lists and `shlex.quote` (no shell strings from input). | — | Verified, no issue | `test_ir::TestExport`, `lab/traffic/orchestrate.py` |
| B10 | Deserialisation | `joblib`/pickle model artifacts execute code on load if replaced. | Medium | **Accepted:** artifacts are operator-written and gitignored. Recommended: a pinned SHA-256 manifest checked before load (STRIDE T3). | — |
| B11 | Info disclosure | `/metrics` is unauthenticated and labels the CERT-In gauge with incident ids. | Low | **Accepted:** restrict `/metrics` at the network/reverse proxy in production (STRIDE I4) | — |
| B12 | Path traversal | `/app/<path>` is served only from a server-built index of `dashboard/dist` (CodeQL fix v4.3.0); replay scenarios come from an enumerated allowlist (v4.2.0). | — | Verified, no issue | `test_soc_session::test_no_path_traversal`, CodeQL |

**Out of scope / not tested:** authenticated fuzzing of every endpoint, load testing, and TLS
configuration of a production reverse proxy.
