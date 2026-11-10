# Incident response backend (M3, v4.2.0)

The IR backend turns detections into tracked incidents with an auditable timeline, playbooks,
a CERT-In reporting timer, exports and time-boxed mitigations. **It never executes mitigation.**
Every block still goes through `PendingActionManager.approve()` with an admin key; the IR code
can only *propose* actions and *revert* (remove) blocks that a human already approved.

Code: `src/ir/` (`db`, `models`, `lifecycle`, `playbooks`, `cert_in`, `export`, `rollback`,
`replay`, `runtime`, `settings`), API `src/api/ir_router.py`, roles `src/api/rbac.py`,
playbooks `playbooks/*.yaml`, replay scenarios `replay/scenarios/*.json`.

## Lifecycle (NIST SP 800-61r3, mapped to CSF 2.0)

```
            ┌───────────────── false_positive ──────────────┐
            │        ▲            ▲             ▲           │
            │        │            │             │           ▼
  new ──► triage ──► investigating ──► contained ──► eradicated ──► recovered ──► closed
 (Detect)  (Detect)   (Respond)        (Respond)     (Respond)      (Recover)    (Recover)
```

- Legal transitions are an explicit table (`TRANSITIONS` in `src/ir/lifecycle.py`). Anything
  else raises `IllegalTransition` (HTTP 409) and writes nothing.
- `contained` needs **≥1 linked action a human approved** (manager status `EXECUTED` or
  `ROLLED_BACK`) **or** a written justification (≥10 chars). Otherwise HTTP 400.
- `false_positive` is reachable from `new`, `triage` and `investigating`, and leads only to `closed`.
- Every change writes an `incident_events` row. Each row stores
  `hash = sha256(canonical{incident_id, seq, ts, actor, kind, detail, prev_hash})`, chained from a
  zero genesis hash. `verify_chain()` recomputes the chain; editing, re-timing or deleting any
  event breaks it. Every incident detail and export reports the result. This makes tampering
  *evident*. It does not prevent it: someone with DB write access could rewrite the whole chain.
  Anchoring the head hash externally is future work.

| CSF 2.0 function | States |
|---|---|
| Detect | `new`, `triage`, `false_positive` |
| Respond | `investigating`, `contained`, `eradicated` |
| Recover | `recovered`, `closed` |

## Roles (deny by default)

Keys map to roles: `DDOS_API_KEYS` → **analyst**, `DDOS_ADMIN_KEYS` → **admin** (admin ⊇ analyst).
No/unknown key → **401**; known key, too little privilege → **403**. Actors are recorded as
`<role>:<pbkdf2(key)[:8]>`, so no key material reaches timelines or exports.

| Endpoint | analyst | admin |
|---|:-:|:-:|
| `GET /api/incidents` (filter `status`, `include_replay`; `limit` ≤200, `offset`) | ✅ | ✅ |
| `POST /api/incidents` | ✅ | ✅ |
| `GET /api/incidents/{id}` (timeline, actions, runs, chain check, suggested playbooks) | ✅ | ✅ |
| `POST /api/incidents/{id}/transition` → `triage`, `investigating` | ✅ | ✅ |
| `POST /api/incidents/{id}/transition` → `contained`, `eradicated`, `recovered`, `closed`, `false_positive` | ❌ 403 | ✅ |
| `POST /api/incidents/{id}/notes` | ✅ | ✅ |
| `POST /api/incidents/{id}/actions` (link an existing proposed action) | ✅ | ✅ |
| `POST /api/incidents/{id}/playbook/{pb}/step/{step}` | if step `requires_role: analyst` | ✅ |
| `GET /api/incidents/{id}/export?format=md\|pdf` | ✅ | ✅ |
| `GET /api/incidents/{id}/cert-in/draft` | ❌ 403 | ✅ |
| `POST /api/incidents/{id}/cert-in/reported` (record a human submission) | ❌ 403 | ✅ |
| `GET /api/playbooks`, `GET /api/replay/scenarios`, `POST /api/replay` | ✅ | ✅ |
| `GET /api/actions/{id}/rollback` | ✅ | ✅ |
| `POST /api/actions/{id}/extend` | ❌ 403 | ✅ |
| `POST /actions/approve/{id}`, `/actions/reject/{id}` (unchanged, scoring service) | ❌ 403 | ✅ |
| `WS /ws/incidents` | ✅ | ✅ |

Inputs are strict pydantic models (`extra="forbid"`). Bad input → 422. Domain errors return
`{"detail": "<message>"}` with 400/404/409. Stack traces are never returned. Untrusted values
are logged through `log_safe()`. This matrix is enforced by `tests/test_ir_api.py::TestRBACMatrix`.

**WebSocket `/ws/incidents`** is server→client only. Authenticate with an `X-API-Key` /
`X-Admin-Key` header on the handshake, or a first message `{"type":"auth","key":"..."}` within
5 s, otherwise the server closes with 1008. Inbound messages are ignored. Event types:
`incident.created`, `incident.transition`, `incident.note`, `cert_in.warning`, `rollback.done`,
`rollback.failed`, `replay.alert`.

## Playbooks

`playbooks/*.yaml` (shipped: `syn_flood`, `udp_reflection_amplification`, `dns_amplification`,
`l7_low_and_slow`, `zero_day_ood`). They are validated at load against a strict pydantic schema
(`Playbook.model_json_schema()` is the JSON Schema). Unknown fields, bad kinds, duplicate step
ids, invalid ATT&CK ids, or an `action` on a non-`propose_action` step are rejected with the
file name and field path.

Step kinds: `check`, `notify`, `document` (recorded as a playbook run plus a timeline event), and
`propose_action`. A `propose_action` step resolves its target (`top_src_ip` / `victim_ip`) from
the incident aggregate, calls **`PendingActionManager.propose()` only**, and links the PENDING
action to the incident with the step's `ttl_s`. An admin must still approve it.
`tests/test_ir.py::TestNoDirectEnforcement` scans `src/ir/` with the AST and fails if any file
calls `approve`, `_execute_action`, `execute` (except on a DB session), `send_msg`,
`subprocess`, or calls `revert` outside `rollback.py`. `tests/test_mitigation_bypass.py` stays green.

## CERT-In 6-hour timer

Basis: CERT-In Directions under section 70B(6) of the IT Act 2000, No. 20(3)/2022-CERT-In,
28 April 2022. Incidents listed in Annexure I must be reported within 6 hours of noticing them —
<https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf>
(see also the CERT-In FAQs, May 2022:
<https://www.cert-in.org.in/PDF/FAQs_on_CyberSecurityDirections_May2022.pdf>). Whether an
organisation is in scope is a legal question for that organisation. This feature only keeps time.

- An incident with `severity ≥ ir.cert_in.severity_threshold` (default 4) gets
  `cert_in_deadline = detected_at + 6 h`. Replay incidents never get one.
- The scheduler (`CertInMonitor.check`) updates `ddos_cert_in_seconds_remaining{incident=…}`.
  It writes a timeline event and a `cert_in.warning` WS event **once each** at 1 h left,
  15 min left, and on breach.
- `GET …/cert-in/draft` (admin) fills the report fields: reporting entity/contact
  (placeholders from config), type of incident, vector, ATT&CK ids, time of occurrence and
  detection, affected IPs/ports, IOCs (raw, or `sha256:` prefixes if `hash_iocs: true`),
  actions taken and timeline. AI-derived fields are listed. **It is a draft. Nothing is ever
  sent to CERT-In.** After a human submits it, `POST …/cert-in/reported` with the
  acknowledgement reference stops the timer.

## Export

`GET /api/incidents/{id}/export?format=md|pdf` produces a summary, analyst output (labelled
**"AI-generated recommendation - review before acting"**), recommended (unexecuted) actions,
actions with approval/rollback state, the full timeline, and the hash-chain result. All
incident-derived strings are escaped. In Markdown, HTML entities are encoded, Markdown
metacharacters backslash-escaped and newlines collapsed, so injected headings, links, tables
and `<script>` stay inert. In PDF, text is XML-escaped before reportlab parses its paragraph
markup.

## Auto-rollback (time-boxed blocks)

- Scope: actions **linked to an incident**. Blocks approved outside an incident keep their
  previous behaviour (no TTL) so existing deployments do not silently start unblocking.
- When a linked action becomes `EXECUTED` (human-approved), `sync()` sets
  `rollback_at = approved_at + ttl`. `ttl` is the step's or link's `ttl_s`, else
  `ir.rollback_ttl_s` (default **600 s**).
- When due, `tick()` calls `PendingActionManager.revert()`. That runs the enforcer's undo
  (OpenFlow `OFPFC_DELETE`, Cloudflare `remove_scrubbing`, or a logged revert for command-style
  actions) and marks the action `ROLLED_BACK`, which also removes the IP from the ingress
  blocklist. Revert can only *remove* a block, and only for an `EXECUTED` action.
- On failure the attempt is recorded (`rollback_failed` event, `ddos_rollbacks_total{result="failure"}`,
  error log, WS event) and retried with exponential backoff
  (`rollback_backoff_s · 2^(n-1)`). After `rollback_max_attempts` (5) the state becomes
  `failed` and the block stays until a human acts.
- Admins can `POST /api/actions/{id}/extend` with `{reason, seconds}` or `{reason, permanent: true}`.
  A reason is always required and is recorded in the timeline.
- Restart-safe: all schedule state lives in the DB. A new process picks up due rollbacks on its
  first tick. The scheduler runs in a daemon thread started in the API lifespan
  (`DDOS_IR_SCHEDULER=off` disables it).

## Replay

`POST /api/replay` with `{"scenario": "syn_flood"}` (or an inline `aggregate`) and `speed`
replays a stored incident aggregate. L1: recorded alerts are re-emitted in order,
time-compressed, capped at 10 s wall time. L2: the stored ML/OOD verdict. L3: the
deterministic rule-based analyst (no LLM call). The result is an `is_replay=True` incident.
Replay incidents use an in-memory **dry-run action manager**: playbook steps on them produce
`dry-…` action ids and the real approval queue is never touched. They are excluded from the
`ddos_incidents` gauge and MTTD/MTTC metrics and get no CERT-In deadline.

*Limitation:* v4.2.0 replays stored **aggregates**. Re-scoring raw flow captures through the
live L1/L2 detectors is not implemented yet.

## Storage and metrics

- SQLite via SQLAlchemy 2.x. URL `ir.database_url` / `DDOS_IR_DATABASE_URL`, default
  `sqlite:///data/ir.db` (gitignored; relative paths resolve to the repo root). No Alembic:
  `create_all` plus a `schema_version` row. The app refuses to open a DB with a newer schema.
  Tables: `incidents`, `incident_events`, `actions`, `playbook_runs`, `schema_version`.
- Metrics on `/metrics`: `ddos_incidents{state}`, `ddos_incident_mttd_seconds` (detection −
  aggregate window start) and `ddos_incident_mttc_seconds` (containment − detection)
  histograms, `ddos_rollbacks_total{result}`, `ddos_cert_in_seconds_remaining{incident}`.

## Config (`ir:` block in every `config/environments/*.yaml`)

| Key | Default | Env override |
|---|---|---|
| `database_url` | `sqlite:///data/ir.db` | `DDOS_IR_DATABASE_URL` |
| `rollback_ttl_s` | 600 | `DDOS_IR_ROLLBACK_TTL` |
| `rollback_max_attempts` / `rollback_backoff_s` | 5 / 10 | — |
| `scheduler_interval_s` | 5 | — |
| `cert_in.severity_threshold` | 4 | `DDOS_CERTIN_SEVERITY` |
| `cert_in.deadline_hours` | 6 | — |
| `cert_in.hash_iocs` | false | `DDOS_CERTIN_HASH_IOCS` |
| `cert_in.org_name`, `contact_*` | placeholders | `DDOS_CERTIN_ORG`, `DDOS_CERTIN_CONTACT_*` |
