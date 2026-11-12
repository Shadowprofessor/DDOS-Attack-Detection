# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [5.4.0] — 2026-11-13

### Added
- **Agentic analyst** (`src/agent/agent_analyst.py`): Lightning (reasoning off) with **read-only** tools.
  Ultra goes first for severity 5 when escalation is on. Same `<telemetry>` sanitising, schema
  validation, retry and rule fallback as before.
  - Tools: live windows, top talkers, baseline comparison, MITRE lookup, playbook, similar incidents,
    containment options.
  - Output: attack type, evidence, reason, confidence, false-positive assessment, and a ranked
    containment plan (action, target, blast radius, reversible, TTL).
  - `POST /api/incidents/{id}/agent` runs it. `.../agent/propose/{rank}` turns one plan step into a
    **PENDING** action. Nothing is executed.
- **Coverage on every lab step:** the share of the attack it would stop, computed by the platform from
  OVS port counters (port drops) or live windows (IP drops), never by the model.
  - A top step under 50% is re-ranked below a better one.
  - If no step reaches 50%, the platform adds the port drop that does.
  - Both changes are recorded in `policy_violations`. The UI shows "Stops ~x%".
- **Human-approved lab containment on OVS** (`lab/containment.py`, `lab/traffic/enforcer.py`).
  - `approve()` only **queues** `LAB_OVS_DROP` / `LAB_OVS_PORT_DROP`. The WSL2 enforcer (root,
    lab-only) re-validates each one and installs `hard_timeout=TTL,actions=drop` with cookie prefix
    `0x5AB0`.
  - Guarded: never the victim, the NAT, or anything outside `10.99.0.0/24`. TTL clamp 30–3600 s.
    Kill switch `lab/KILL` removes every `0x5AB0` rule.
  - Every state change is logged (queued → applied → expired/removed) and relayed by the bridge.
- **Triage accuracy** vs lab ground truth (`scripts/triage_accuracy.py`, `docs/eval/triage/`).
- **MTTC** measured from the switch's own counters (`scripts/live_mttd.py`, `docs/eval/live/`).
- `scripts/demo_assist.py`: runs the agent and proposes the top lab step for new live incidents. It
  uses an analyst key, so it cannot approve.
- Demo catalogue (`lab/scenarios/demo/`, 120 s SYN and UDP floods); `CONTAIN=1 bash lab/live_demo.sh`.

### Measured
| | Rules | Lightning | ML (L2) |
|---|---:|---:|---:|
| Attack type correct, DEV / held-out | 10/10 / 10/10 | 8/10 / 8/10 | 7/10 / 7/10 |
| Family correct, DEV / held-out | 10/10 / 10/10 | 7/10 / 7/10 | 8/10 / 8/10 |
| False alarms (benign, flash crowd) | 0% | 0% | 0% |

Lightning's errors: NTP reflection → "Benign / flash crowd", LAND → "SYN flood", novel mix → wrong family.

- **Live containment (live8):**
  - Approval → rule on the switch: **0.61 s**.
  - **MTTC** (approval → victim below 100 pps for 2 samples): **2.63 s**.
  - Victim rate 2,997 → 0 pps (100%). Attack start → contained 41.16 s (most of it is the human
    approving).
  - The same 300 s port rule also kept the second (UDP) flood out until it expired. That flood was
    then detected about 1.5 s after expiry.
- **Live MTTD on the website, live4–live8 (7 floods):** 2.66–8.55 s, median 4.89 s.
- **Recorded as measured:** Lightning called the live **UDP** flood a "SYN flood" in live4, live5 and
  live8. It was right in live7 (ML had said SYN). It named every SYN flood correctly.
- **live5:** the approved single-IP drop stopped **2%** of a 50-source flood; MTTC was not reached.
  This led to the coverage ranking above.

### Fixed (found in live runs)
- `/score/flow` proposed blocking the victim (live4).
- Per-window logging lagged the bridge by 7 s; it is now batched (live4).
- A demo YAML with an unquoted colon broke the lab run (live3). Every catalogue now has a parse test.
- WebSocket double-close error.
- The bridge exited when the server was not up yet, which lost run live6. It now waits.
- **Stale approvals:**
  - An approval not applied within its TTL expires.
  - A proposal older than its TTL cannot be approved.
  - The enforcer refuses approvals made before it started (live5 and live8).
- `/score/flow` no longer proposes host iptables blocks for lab addresses. On Approvals they were
  approved instead of the lab step (live7).

### Safety
- Unchanged: the AI only recommends, and every lab rule is applied only after
  `PendingActionManager.approve()` by an admin key. `tests/test_mitigation_bypass.py` stays green.
- No auto-approve option was added.

## [5.3.0] — 2026-11-12

### Pre-fixes from v5.2.0
- **Chat:** the offline fallback never invents a number. Missing data reads "unknown", and an
  AST + data test fails if a number is invented.
- **Command check:** sysctl keys, `DDOS_*`/`NEMOTRON_*` settings and script flags in chat answers
  are checked against real Linux keys and this repo's code. Anything else is marked "unverified —
  check before running".
- **`/score/flow` rate corroboration no longer flags benign traffic.**
  - H6 rate = events / window. It used to divide by the gap between samples, so two benign flows
    50 ms apart read as 480 pps.
  - H9 is a per-destination adaptive EWMA baseline. It used to be one fixed ~2 pps baseline.
  - A "campaign" needs rate evidence, not just ≥ 3 sources.
  - DEV: benign 88/90 → 0/90, flash crowd 90/90 → 0/90.
- Models that did not run are "not scored"; they used to get placeholder Benign 0.56/0.66 entries.
- Lightning is the primary model everywhere in the docs; the live demo standardises on port 8000
  (`DDOS_API_URL`).
- **Recorded as measured:** in live2, Lightning called the **UDP** flood "Benign / flash crowd". It
  named the SYN flood correctly.

### Added
- **Explanations on every detection:** `detected_by`, `attack_type`, `confidence` (None for
  threshold rules), MITRE, and a plain-language `reason` with the numbers.
  - Covers live L1 alerts, L3 analyses (rules or LLM, with the rule verdict alongside the LLM's)
    and `/score/flow`.
  - Shown on the Live Attack banner, the incident page ("Why it was flagged") and the
    Markdown/PDF export.
- **L3 rules, tuned on DEV runs 2+3:**
  - half-open SYN flood (handshake completion instead of a single 0.67 vs 0.7 ratio);
  - ACK, RST and LAND (source IP == destination IP);
  - DNS / NTP reflection by **source** port;
  - unclassified multi-protocol flood; carpet-bombing.
  - They work on offline flows and on live windows: DEV went from 7/12 to 12/12 named.
- **Handshake-aware low-and-slow:** a connection only counts after the server answered and the
  client sent bytes. Live slow-connection counts come from all flows; DEV live alert at 18 s.
- **Flash-crowd guard:**
  - per-destination adaptive baseline;
  - benign signals (complete two-way conversations, TCP data) suppress WARNING-level rate
    verdicts. CRITICAL always alerts.
- **Lab:** a labelled training catalogue (22 variants, none equal to an evaluation configuration),
  per-run `--seed` (it was always 1, so runs were near-copies), and `--catalog main|train`.
- **L2 retrained (XGBoost) on CIC + lab `train1`,** with the recipe and deploy rule fixed in
  advance. `DDOS_XGB_MODEL` selects the artifact.
  - CIC leakage-safe macro-F1 0.906 → 0.917 (benign FPR 0.06% → 0.13%).
  - **Held-out run4:** 0.018 → **0.800**, attack detection 20% → **99.95%**.
  - Weak classes: ICMP, reflection, Slowloris.
- `scripts/train_lab_l2.py`, `scripts/coverage_compare.py`, and `docs/purple_team/{dev,heldout}/`.

### Measured: DEV vs HELD-OUT (rules frozen at `2e0afab` before run4 was analysed)
- DEV 10/10 attacks detected, 2/2 benign clean. **HELD-OUT 10/10 detected, 10/10 expected family,
  2/2 benign clean.** Flood MTTD 1.2–1.4 s.
- **Held-out finding:** L2 labels 2-packet TCP connection fragments, sent by the victim just before
  two scenarios started, as "ACK": 12 flows. Raw MTTD was negative there. Counting only flows
  after the start: ICMP 0.15 s, low-and-slow 118.1 s. Not tuned away.

### Fixed
- Flow-level SYN+FIN signature requires ACK == 0. Normal connections matched it.
- The slow detector got real ports. CICFlowMeter features have none, so 300 connections
  collapsed into 3.
- Lab analysis: fresh L1 state per scenario (the previous flood leaked into the next), L1 always
  recomputed, and the cache fingerprint covers the artifacts in use + the mode.

## [5.2.0] — 2026-11-12

### Added
- **Live: Mininet attack → SOC website in real time.**
  - **WSL side:** `lab/live_demo.sh` (sudo) runs the existing gated generator with a demo sequence
    (benign → SYN → ICMP → flash crowd → UDP), the containment proof, `tcpdump -U` per scenario,
    and a read-only OVS `dump-ports` poller.
  - **Windows side:** `scripts/live_bridge.py` tails the growing pcaps and port counters on the
    shared disk and feeds the platform through its API only. No WSL2↔Windows network path or
    firewall change is needed.
  - **Sensor (`src/live/`):** incremental pcap reader (no scapy, safe on half-written records),
    per-victim 1 s windows (pps, bps, sources, entropy, protocol/flag mix, sizes, top talkers),
    and flow snapshots every 5 s, so long floods are scored while still running.
  - **Platform:** `/api/live/windows|flows|ovs|state|reset` + `/ws/live`. L1
    (`RateThresholdDetector`) runs on every window; alert episodes open and clear; OVS port rates;
    Prometheus gauges. Strict schemas and a separate write rate limit.
  - **Bridge actions:** opens an incident through the IR API for each alert and runs the analyst
    (in the background). Relays `/score/flow` verdicts labelled with what decided them (ML vs rate
    corroboration).
  - **Web:** a **Live attack** page with pps/bps charts, an alert banner with the L1 rule and its
    numbers, top attackers, protocol/flag mix, OVS port counters, incidents and alert history.
  - **Tools:** `scripts/live_mttd.py` (real-time MTTD from manifest × bridge log) and
    `scripts/pcap_replay_live.py` (re-writes a recorded pcap as a growing file; sends nothing).
  - Runbook block H.
- **Measured live (2 lab runs, `docs/DETECTION_LATENCY.md`):**
  - Alert on the website **3.8–5.8 s** after attack start: SYN 5.83 s, ICMP 3.89 s, UDP 3.77 s.
    ~2 s of that is WSL2→Windows disk visibility.
  - ICMP 3.9 s live vs 55.8 s offline.
  - **No live alert on benign or flash crowd.**
  - L3 via Nemotron Lightning named the SYN and ICMP floods but called the **UDP flood "Benign /
    flash crowd"** (wrong). The rule analyst missed SYN. ML (L2) did not detect SYN or ICMP.
- **SOC chat answers any question.** Live state, incident response (with the incident's playbook),
  and securing the network, via Nemotron with conversation history and incident scope.
  - Approve/block requests still get the safety notice, then the advice and the matching pending
    proposal. There is still no execution path.
  - Checked live against Lightning. Its commands are recommendations to review: it invented a
    sysctl name once, and the prompt now forbids guessing.
- Approvals is visible to analysts (read-only, with a note to sign in as admin to act).

### Fixed
- **Live alerts cleared mid-attack (live1).** Pcap writes reached Windows 1–3 s late, and windows
  were closed by the wall clock meanwhile. Floods went out as empty windows, and the alert cleared
  after 5–18 s of a 60 s flood. Windows now close by the packet clock while packets arrive, and by
  the wall clock only after 2 s without packets. Late packets are counted. live2: one alert per
  flood for its full duration, 0 late packets.
- The bridge waited on LLM analysis inside its loop (live2 post lag up to 12.9 s). Analysis now
  runs in a background thread with a 120 s timeout. Tested; not yet re-measured in a lab run.
- The chat's offline fallback printed **hard-coded numbers** ("13 validation test pcaps, 6 clean
  passes…"). It now uses only real platform state plus standard guidance, and says it is offline.
- The chat refused any question containing "block"/"approve" instead of advising.

### Known issues (measured, not fixed here)
- `/score/flow` rate corroboration calls benign flows "attack" when a victim has ≥ 3 flows from
  ≥ 3 sources: 16–20 s into the benign and flash-crowd phases in both runs, with the ML saying
  Benign. It is labelled honestly in the UI; the fix is planned for v5.3.0.
- `/score/flow` fills placeholder per-model entries ("Benign 0.56/0.66") when corroboration
  overrides a missing model (v5.3.0 explainability).

## [5.1.0] — 2026-11-11

### Changed
- **L3 analyst default model: Nemotron 3.5 Lightning** (`nvidia/nemotron-3.5-lightning-30b-a3b`).
  The id and forced tool calling were verified on the live NIM model list.
  - Override with `NEMOTRON_MODEL`, or with `DDOS_LLM_MODELS` for a chain.
  - **Ultra** (`nvidia/nemotron-3-ultra-550b-a55b`) is now an optional escalation for incidents the
    rules rate severity 5: `DDOS_LLM_ESCALATE_ULTRA=true`, **off by default**.
  - The rule-based fallback is unchanged. Tests and CI still use rules or mocks; the live test
    skips without `NVIDIA_API_KEY`.
- **Live NIM result, run once, reported as measured.**
  - The first Lightning call returned no content: reasoning used 911 of 1,024 tokens
    (`finish_reason=length`).
  - The legacy agent now sends `enable_thinking: false` (opt back in with
    `NEMOTRON_ENABLE_THINKING=true`) and handles null content. The live test then passed in 7.9 s.
  - The probe's forced tool call returned severity 8, outside the 1–5 range. Validation, retry and
    the rule fallback cover this.

### Added
- **Four lab scenarios** on the existing gated generator, with the same caps, kill switch and
  containment (no new safety model):
  - `icmp_flood` (T1498.001), `tcp_ack_flood` (T1498.001), `tcp_rst_flood` (T1498.001),
    `land_attack` (T1499.001).
  - Measured in lab `run3`: 282,032 packets; containment check passed again.
  - **ICMP: detected** (L1 + L3). **ACK: partial** (L1; L2 flagged but as UDP reflection; L3 not
    detected). **RST: partial** (L1; L3 not detected). **LAND: partial** (one flow; L3 called it a
    SYN flood).
- `lab_analysis` and `detection_latency` accept several run directories (a later run wins per
  scenario). The per-flow score cache is keyed by a model fingerprint, so changing a model can't
  reuse stale scores.
- Coverage matrix, purple-team findings 8–11, `REPORT.md` §5.3 and README "what's measured" now
  cover 12 scenarios.

### Fixed
- **L3 SYN-flood mislabel (lab harness).** The lab aggregate counted every flow to 80/443 as an
  HTTP request, including zero-payload handshakes. So the SYN flood read as "HTTP flood" and then
  "Slowloris", and ACK/RST floods as "Slowloris". Only flows with client payload count as HTTP now;
  HTTP scenarios are unchanged.
  - **Measured after the fix: L3 does not detect the SYN, ACK or RST floods.** The SYN rule needs a
    SYN ratio ≥ 0.7, and an answered SYN flood is 2/3. Not retuned against the evaluation run.
- Coverage no longer prints an L3 family when L3 did not alert.
- Lab containment failed on a Windows checkout (CRLF in `containment.nft`). Added `.gitattributes`
  (LF for lab files) and the orchestrator strips CRs.

### Investigated, not changed: L2 missed the lab SYN flood (0/1,452)
- **No feature is missing.** The lab SYN flows are 17 µs answered handshakes. CIC-DDoS2019 `Syn`
  flows are ~40 s and mostly unanswered.
- In the training set, flows of the lab shape are **212 `Syn` vs 9,762 `Benign`**, so the
  ensemble's `Benign` is what its training data supports.
- **Not retrained.** An honest fix needs labelled lab-shaped traffic independent of the evaluation
  run. Retraining on CIC-DDoS2019 cannot fix it, and training on `run2` would leak. Documented in
  `REPORT.md` §7 and `docs/purple_team/README.md` finding 1.

## [5.0.1] — 2026-11-11

Docs and a benchmark script only. **No behaviour change.**

### Added
- `docs/RUNBOOK.md`: copy-paste blocks for every way to run the system. Covers one-time setup
  (Windows + WSL2 lab packages), the SOC app with demo keys, scoring one attack flow → PENDING
  proposal, replaying a scenario, the Mininet lab (sudo, ~11 min, kill switch), analysing pcaps →
  coverage matrix, and the full test suite (CI parity). Each block has expected output, how to
  stop it, and whether it needs WSL2/sudo. Blocks B–D were run live, in bash and PowerShell.
- `scripts/detection_latency.py` + `docs/DETECTION_LATENCY.md`: detection time from real data.
  - Per-stage processing latency on 1,600 real lab flows (p50/p95/p99): L1 0.28 ms, L2 RF+XGB
    67.0 ms, OOD 13.1 ms, **end-to-end ~81 ms/flow** (p50), L3 rules 0.13 ms per incident.
  - Per-layer MTTD per scenario from the lab run: L1 0.9–2.2 s on floods and 117 s on
    low-and-slow. Layers that never fired are reported as "not detected". Explicitly an upper
    bound (ramp-up, aggregation windows, flow completion).
  - Raw numbers in `docs/eval/latency/results.json`.
- `tests/test_detection_latency.py` (6): the benchmark on a tiny synthetic set (fast in CI).
- README: pointers to both docs.

## [5.0.0] — 2026-11-11

### BREAKING CHANGES
- **Legacy dashboard removed.** `src/web/realtime_dashboard/static/` (HTML/JS/CSS) and the
  standalone `Codes/dashboard/app.py` are gone. `/dashboard` and `/legacy` return **308 → `/app/`**,
  `/` redirects to `/app/`, and `/dashboard/static/*` is 404. The JSON endpoints and the
  `/ws/dashboard` stream are unchanged; the SOC app's live feed uses them.

### Added
- **Technical report** `REPORT.md`: architecture, design decisions, safety model, evaluation
  (same-dataset vs cross-dataset vs lab, numbers as measured), threat hunts, limitations, future
  work, references.
- **GRC:** `docs/grc/control_mapping.md` (platform controls → NIST CSF 2.0, ISO/IEC 27001:2022
  Annex A, CIS v8, CERT-In, MITRE D3FEND, each with evidence and coverage) and
  `docs/grc/risk_register.md` (12 risks, likelihood × impact, inherent and residual).
- **Citation check:** `scripts/check_citations.py` verifies every URL and arXiv id in REPORT,
  README and the GRC/eval/lab docs resolves. Dead links fail; bot-blocked sites warn. New CI job
  `Citation check`.
- **60-second demo** `docs/DEMO.md`. README gains an architecture diagram, an updated version
  history and roadmap, a web-app badge, and links to the report and GRC docs.

### Changed
- The bypass audit (`tests/test_mitigation_bypass.py`) now audits the React app. There is exactly
  one approve call site (`Approvals.tsx`), reachable only from the confirmation dialog, through
  the CSRF-carrying `api()` client. The guarantee is kept, not dropped.
- The legacy `app.js` escaping test is replaced by a scan of the React app for raw-HTML sinks and
  browser storage, plus the ESLint ban.
- The live feed shows the **DEGRADED** badge and reason (previously only in the legacy UI).

### Known issue
- The opt-in live NIM test (`tests/test_nvidia_nim_live.py`, runs only with `NVIDIA_API_KEY`)
  still fails at release time: the legacy agent's 60 s read timeout to `integrate.api.nvidia.com`
  (after a 503 earlier). The rule-based fallback engages as designed. The timeout was not raised
  just to make the test pass. CI does not run this test (no key).

## [4.7.0] — 2026-11-11

### Added — threat hunting + security self-assessment
- **Two hypothesis-driven hunts** (`docs/hunts/README.md`, rules in `src/hunt/rules.py`):
  H1 low-rate distributed reflection (≥50 reflectors, each ≤20 pps, together ≥200 pps from
  amplification source ports) and H2 distributed slow-read L7 abuse (long HTTP flows with tiny
  client windows and starved downloads across ≥10 sources). Both were executed over the v4.6.1
  lab flows (~221k): **no findings**, which is expected for that data. Inputs were verified as
  populated, and neither rule fires on the flash crowd. Not yet validated on positive traffic.
- **STRIDE threat model** (`docs/security/STRIDE.md`): 18 threats, each with its in-code
  mitigation, the test/CI evidence, and residual risk.
- **Bug-hunt report** (`docs/security/bug_hunt.md`): 12 items covering authz/IDOR, CSRF, SSRF,
  injection, deserialisation, rate limits and more.

### Fixed (bug hunt)
- IR write endpoints had no rate limit. Now limited per actor (`DDOS_IR_WRITE_RATE_PER_MIN`, 120).
- `/api/chat` (each message may be an LLM call) had no rate limit. Now limited per key
  (`DDOS_CHAT_RATE_PER_MIN`, 20).
- `/api/chat` no longer returns 500 on a non-object JSON body; messages are capped at 2,000 chars.

### Tests
- `tests/test_hunt_rules.py` (11, positive + negative per rule), `tests/test_bug_hunt_fixes.py` (7).
- Gated like CI (no `NVIDIA_API_KEY`). The opt-in live NIM test failed locally on two runs because
  of the NVIDIA endpoint (60 s read timeout, then HTTP 503), not because of a code change. It is
  re-checked before v5.0.0.

## [4.6.1] — 2026-11-11

### Added — purple-team lab runs (owner-approved traffic generation; docs: `docs/purple_team/README.md`)
- `lab/traffic/generator.py`: LAB-ONLY gated generator. It runs only after `lab.safety` planning
  passes: WSL2 + a Mininet host network namespace, allowlisted lab scope, caps, kill switch.
  Every packet's source and destination are re-checked, total packets are capped, and the kill
  switch is checked every tick. Sending lives in `_emit_*` functions reachable only through
  `GatedTrafficRunner` (AST-tested). It reports `achieved_pps`.
- `lab/traffic/orchestrate.py`: isolated Mininet LAN (OVS, no NAT/route out), per-scenario victim
  pcaps. The manifest is saved after every scenario.
- `--containment`: a separate net with a deliberately opened NAT path. nftables
  (`lab/traffic/containment.nft`) must drop lab egress. Verdict is contained / NOT contained /
  inconclusive, with diagnostics.
- `src/eval/lab_analysis.py`: pcaps → real L1 (threshold + signature + low-and-slow) / L2 ensemble
  / OOD / rule L3 → coverage matrix, MTTD, false positives, ATT&CK Navigator layer
  (`docs/purple_team/{results.json,coverage.md,navigator_layer.json}`).

### Results (first measured run, reported as measured)
- **Containment proven.** 3/3 probes to TEST-NET-1 reached the boundary and were dropped; 0 on
  the uplink.
- **Detected:** UDP flood, NTP reflection, HTTP low-and-slow. **Partial:** SYN flood (L3 called it
  low-and-slow), DNS reflection (generic UDP family), novel/OOD mix (OOD 48%).
  **False positives:** flash crowd (L1 on 41% of flows), benign baseline (3%).
- **L2 ensemble flagged 0 of 1,452 sampled lab SYN-flood flows** and 1–16% for the other floods.
  Consistent with v4.4.0: the classifier does not transfer beyond CIC-DDoS2019.
- MTTD ≈ 1 s after flow export (≈ 61 s including a 60 s idle-timeout export); low-and-slow 117 s.

### Fixed
- `family_from_text()` matched "ood" inside "fl**ood**", so "UDP flood" analyses were routed to
  the zero-day playbook. Now whole-word matching, with a regression test.

## [4.6.0] — 2026-11-11

### Added — purple-team lab safety layer (docs: `docs/purple_team/README.md`). No traffic generation.
- `lab/lab_scope.yaml` + `lab/safety.py`: code-enforced scope. Allowed networks must be private,
  at most /16, and not loopback/link-local/multicast/reserved. Every host role must be inside
  them. Public IPv4/IPv6 and non-allowlisted private targets are refused. Rate, duration and
  concurrency are capped. Kill switch: file, env var or `trip()`. The runner refuses to start
  unless WSL2 **and** Mininet are detected.
- `lab/scenarios/*.yaml` + `lab/library.py`: 8 scenarios (benign baseline, flash crowd, SYN flood,
  UDP flood, simulated NTP and DNS reflection, HTTP low-and-slow, novel/OOD mix), each mapped to
  ATT&CK with expected family, layers and MTTD budget. The schema forbids extra fields (no
  commands, no raw addresses).
- `lab/runner.py`: mock runner. Every safety check, then per-tick *descriptions* only (no
  packets). The kill switch is re-checked before every tick. `to_aggregate()` builds a synthetic
  aggregate for a replay-based pipeline check (documented as *not* detection evidence).

### Tests
- `tests/test_lab_safety.py` (37):
  - public and non-allowlisted targets refused, bad scope networks rejected;
  - caps enforced; refuses to start outside the lab;
  - kill switch stops a running scenario within one tick and blocks start (file + env);
  - scenario validation, mock pipeline wiring;
  - **AST scan: `lab/` contains no networking/process code**.

## [4.5.0] — 2026-11-11

### Added — SOC web app, part 3 (docs: `docs/SOC_APP.md`)
- **Live feed** page: `/ws/dashboard` stream over the session cookie (same-origin), with
  filters, pause/resume and a windowed list (2,000 events kept).
- **Replay** page (scenario + speed → replay incident, stages shown, dry-run proposals only).
- **AI analyst** chat page (read-only `/api/chat`, optional incident scope, provenance shown).
- **Settings & health** page + `GET /api/system` (versions, model artifacts, analyst config with
  key presence only, IR settings).
- Legacy dashboard served at `/legacy` too. Both URLs send `Deprecation` / `Link` /
  `Warning` headers. Removal is in v5.0.0.
- README screenshots in `docs/img/`, captured by an opt-in Playwright spec.

### Changed
- `/api/chat`, the legacy dashboard JSON endpoints and `/api/analyst/config` accept the web-app
  session (CSRF on POST). `/ws/dashboard` accepts a same-origin session cookie. The cookie check
  is shared with `/ws/incidents` via `rbac.ws_session_key`.
- Scored-flow broadcasts now include `src_ip` / `dst_ip`. Without them the feed could not show
  who was talking to whom.

### Fixed
- Long incident titles in a dropdown widened the AI analyst page past a 375 px screen. Stat
  cards on the overview were vertically misaligned.

### Tests
- pytest `tests/test_soc_pages.py` (7): session chat + CSRF, analyst config via session,
  `/api/system` has no secrets, legacy deprecation headers, `/ws/dashboard` cookie auth +
  cross-origin rejection.
- Vitest 23 (+3). Playwright 21 (+8): **axe-core 0 serious/critical on every page**, no CSP
  violations, 375 px on every page, reduced motion, live feed receives a scored flow, replay,
  chat refuses to act, settings shows no secrets, legacy deprecation.

## [4.4.0] — 2026-11-11

### Added — cross-dataset evaluation (docs: `docs/eval/cross_dataset.md`)
- `src/eval/cross_dataset.py`: CIC-DDoS2019-trained ensemble tested on a CICIoT2023 CSV sample
  (Benign / DDoS-SYN_Flood / DDoS-UDP_Flood, 2,000 rows each, fixed seed, SHA-256 manifest).
  Option B mapping: 20 of 77 CICFlowMeter features have a CICIoT2023 counterpart. The other 57
  are filled three ways (zero / CIC-DDoS2019 Benign median / production heuristic), plus a non-ML
  protocol/flag baseline. Results in `docs/eval/cross_dataset/results.json`; the doc table is
  generated from it.

### Results (reported honestly: inconclusive)
- Attack F1: **1.000** (zero fill), **0.050** (benign-median fill), **0.966** (production path;
  benign FPR **14.2%**). The protocol rule alone: F1 0.916, benign FPR **36.9%**.
- These numbers depend on how the unmapped features are filled, and the three classes are easy
  to separate by protocol and flags. This measures sensitivity to a feature-schema mismatch,
  **not** generalisation. The OOD detector flagged ~0% of these shifted inputs.
- **The same-dataset caveat stays.** No same-extractor test (pcaps through our CICFlowMeter
  extractor) has been run.

### Tests
- `tests/test_cross_dataset.py` (9 + 1 slow opt-in): mapping coverage, deterministic seeded
  sampling + manifest, imputation strategies, metrics on a known scorer, family rules, baseline
  reproduction against the committed results, doc table == results.json. `DDOS_RUN_SLOW=1`
  re-runs the ensemble and compares exactly.

## [4.3.1] — 2026-11-11

### Added — SOC web app, part 2 (docs: `docs/SOC_APP.md`)
- **Incident detail** page: lifecycle actions by role (containment dialog with justification),
  AI analyst panel labelled as a recommendation with provenance, aggregated telemetry, playbook
  runner ("Request action" only proposes), linked actions with rollback state, notes,
  hash-chained timeline with verification status, MD/PDF export, CERT-In draft + "mark reported"
  (admin).
- **Approvals** page (admin): pending actions with estimated blast radius, reversibility,
  rollback TTL and incident link; approve or reject (with reason) through a confirmation dialog;
  active blocks with a live rollback countdown, extend or make permanent (with reason).
- **Live updates** over `/ws/incidents` with session-cookie auth (same-origin handshakes
  only), reconnect with backoff, polling fallback, status chip.
- API: `GET /api/approvals` (read-only feed) and `POST /api/incidents/{id}/analyze` (stores the
  analyst result on the incident; never proposes or executes). `/actions/approve|reject|pending`
  accept the web-app session + CSRF.

### Fixed
- `requirements.txt` now pins `websockets==16.0`. Plain `uvicorn` has no WebSocket library, so
  a fresh install rejected every `/ws/*` upgrade (dashboard and incidents). Local runs passed
  only because the package happened to be installed. Caught by the Playwright live-update test
  in CI.

### Tests
- pytest `tests/test_soc_detail.py` (12): session approve/reject + CSRF, analyst 403, approvals
  feed + countdown, analysis stored without new proposals, WS cookie auth + cross-origin reject.
- Vitest 20 (+5). Playwright 13 (+5): analyst workflow (triage, note, playbook steps, AI panel,
  MD/PDF download), analyst approve via API → 403, admin approve → countdown, keyboard-only
  extend, contain with justification + CERT-In draft, live WS update without reload.

## [4.3.0] — 2026-11-10

### Added — SOC web app, part 1 (`dashboard/`, docs: `docs/SOC_APP.md`)
- React 19 + Vite 8 + strict TypeScript app served by FastAPI at `/app`, with a
  traversal-safe page fallback that never shadows `/api`. Pinned `package-lock.json`.
- **Login** exchanges an API key for a server-side session (`ddos_session`: HttpOnly, Secure,
  SameSite=Strict). New id on every login, idle + absolute expiry, role re-checked every request,
  login rate limit. `GET /api/session`, `POST /api/session/logout`.
- **CSRF**: synchroniser token required on cookie-authenticated mutations (403 otherwise);
  header-key API clients unchanged.
- **Strict CSP** (no `unsafe-inline`/`unsafe-eval`) + nosniff, no-referrer, Permissions-Policy,
  frame denial on `/app*` and `/api/*`; HSTS in production/staging.
- **Overview** page + `GET /api/overview`: open incidents, pending approvals, MTTC,
  false-positive rate, open-by-severity chart, CERT-In countdowns, recent incidents, health.
- **Incidents** page: filter, sort, paginate. `GET /api/incidents` gains `sort` and `min_severity`.
- Dark theme (cyan / violet / amber; red only for severity 5), skip link, visible focus,
  reduced-motion, no horizontal scroll at 375 px.
- CI workflow `webapp.yml`: lint, typecheck, Vitest, build, `npm audit --audit-level=high`,
  Playwright against the real API. Dependabot for npm.

### Changed
- CORS is same-origin by default (was `*`); set `DDOS_CORS_ORIGINS` to allow listed origins.

### Tests
- pytest `tests/test_soc_session.py` (20): cookie flags, rotation, expiry, revocation, CSRF,
  CSP/headers, SPA fallback + traversal, overview. `test_ir_api.py` +1 (sort/filter).
- Vitest (15): API client (CSRF only on mutations, same-origin only, error mapping), auth store
  (memory-only), severity colours. Playwright (8): login, bad key, list filter/sort/paginate,
  XSS renders as text, logout, cookie flags + no key in storage, CSRF-less POST → 403, 375 px.

## [4.2.0] — 2026-11-10

### Added — M3: incident-response backend (`src/ir/`, docs: `docs/IR.md`)
- **Persistence**: SQLite via SQLAlchemy 2.x (`ir.database_url`, default `data/ir.db`);
  tables `incidents`, `incident_events`, `actions`, `playbook_runs`, `schema_version`.
- **NIST SP 800-61r3 lifecycle** `new → triage → investigating → contained → eradicated →
  recovered → closed` (+ `false_positive`), explicit transition table, CSF 2.0 mapping.
  `contained` requires a human-approved action or a written justification.
- **Tamper-evident timeline**: every event is SHA-256 hash-chained; `verify_chain()` is shown on
  every incident and export.
- **YAML playbooks** (`playbooks/`: SYN flood, UDP reflection/amplification, DNS amplification,
  L7 low-and-slow, zero-day/OOD) with strict schema validation. `propose_action` steps only call
  `PendingActionManager.propose()`.
- **CERT-In 6-hour timer** (Directions No. 20(3)/2022-CERT-In, 28.04.2022): deadline for
  severity ≥ threshold, `ddos_cert_in_seconds_remaining`, warnings at 1 h / 15 min / breach,
  report **draft** (never auto-submitted), "reported" acknowledgement.
- **Export**: Markdown and PDF (reportlab) incident reports with escaped untrusted text and
  AI output labelled as a recommendation.
- **Auto-rollback**: incident-linked approved blocks revert after a TTL (default 600 s) via the
  new `PendingActionManager.revert()`. Retry with backoff, restart-safe, admin extend/permanent
  with reason.
- **Replay engine**: stored incident aggregates go through L1 → L2 → rule-based L3 into
  `is_replay` incidents, with a dry-run action manager (no real proposals).
  Scenarios in `replay/scenarios/`.
- **API** (`src/api/ir_router.py`): incidents CRUD/transition/notes/actions/playbook steps,
  export, CERT-In draft/reported, replay, rollback status/extend; `WS /ws/incidents`
  (auth on connect, server→client only).
- **RBAC** (`src/api/rbac.py`): `analyst` (`DDOS_API_KEYS`) vs `admin` (`DDOS_ADMIN_KEYS`), deny by
  default, correct 401 vs 403. Actors are recorded as key fingerprints, never key material.
- **Metrics**: `ddos_incidents{state}`, MTTD/MTTC histograms, `ddos_rollbacks_total{result}`,
  CERT-In remaining. A dependency-free `Histogram` was added to `src/obs/metrics.py`.
- `ir:` config block in all six environment YAMLs.

### Changed
- `requirements.txt` pinned to exact, tested versions; added `sqlalchemy`, `reportlab`;
  bumped `requests` 2.34.2, `scapy` 2.8.0, `pyyaml` 6.0.3 (pip-audit: 0 known vulnerabilities).
- CI runs on Python 3.14 (numpy 2.5 / xgboost 3.4 have no 3.11 wheels).

### Tests
- `tests/test_ir.py` (54) and `tests/test_ir_api.py` (15): lifecycle legal/illegal matrix,
  hash-chain tamper cases, playbook validation, PENDING-only proposals, AST guard that `src/ir/`
  never approves or executes, CERT-In timing with an injected clock, export escaping and PDF
  round-trip, rollback TTL/extend/restart/retry, replay isolation, RBAC endpoint × role matrix,
  422 without traces, WS auth.

## [4.1.1] — 2026-11-10

### Security — fixes for all open CodeQL high/medium alerts (19, pre-existing from v4.0.x)
- **DOM XSS (4 high)** in the legacy dashboard `static/app.js`: every server-derived string
  (IPs, action IDs, labels, caveats, dossier text, commands) is now passed through `escapeHtml`
  before `innerHTML`. `escapeHtml` no longer drops `0` values.
- **Remote property injection (1 high)**: taxonomy counts use a `Map`, so a flow label such as
  `__proto__` cannot pollute the object prototype.
- **Path injection (1 high)** in legacy `Codes/dashboard/app.py`: incident IDs used in file names
  must match `[A-Za-z0-9_-]{1,64}`.
- **Clear-text secret (1 high)**: generated dev keys are written to an owner-only `.dev-keys`
  file (gitignored, override with `DDOS_DEV_KEY_FILE`); only the path is printed. Prod/staging
  still refuse to start without configured keys.
- **Log injection (8 medium)**: new `src.obs.logging.log_safe()` escapes CR/LF and truncates
  untrusted values in the scoring service, mitigation manager and WS broadcaster.
- **Stack-trace / error exposure (1 medium)**: a failed approval returns a generic 500; the
  detail goes to the server log only.
- **Incomplete URL check (3 high, tests only)**: tests compare `urlparse(...).hostname`.

### Tests
- `tests/test_codeql_hardening.py` (log injection, path allowlist, no error leak, JS escaping).
- Dev-key test now checks the key is in the file and NOT in stdout or logs.

## [4.1.0] — 2026-11-10

### Added — M2: Nemotron AI threat analyst (Layer 3)
- `POST /api/analyst/analyze`: analyses ONE aggregated incident (`IncidentAggregate`) and
  returns a strict, validated `AnalysisResult` (attack type, MITRE IDs, severity 1-5,
  confidence, evidence, false-positive assessment, ranked recommended actions, next queries,
  report summary). Recommendations only - no path to any enforcer. API key + per-key rate limit.
- `GET /api/analyst/config`: non-secret analyst configuration.
- Versioned system prompt `prompts/threat_analyser.md`; strict JSON via forced tool-calling;
  pydantic validation -> retry once -> deterministic rule-based fallback.
- Config-driven model chain (`analyst:` YAML section / `DDOS_LLM_MODELS`), IDs verified against
  the live NIM model list: `nemotron-3-ultra-550b-a55b` -> `nemotron-3-super-120b-a12b` -> rules.
- One cached analysis per incident window; 90 s timeout; optional HMAC IP pseudonymisation.
- LLM latency / token / estimated-cost / cache / fallback / policy metrics on `/metrics`.
- Prompt-injection evaluation: 32 payloads x 3 conditions on live Nemotron, plus a held-out
  detector set and benign false-positive set (`src/agent/injection_eval.py`, EVAL_NOTES §6).

### Security
- Layered prompt-injection defence: sanitiser (invisible chars stripped, tags escaped, bounded
  strings, `<telemetry>` wrapping) + untrusted-data system prompt + **code-enforced output
  policy** (pinned incident ID, human approval forced on every action, foreign-IP actions
  dropped, injected downgrades overridden or flagged `llm_ml_disagreement`, canary redaction).
- `/api/chat` now routes through the hardened client and sanitises its live context.

### Known limitations
- `nemotron-3-super-120b-a12b` is in the NIM catalog but returns 404 for this account, so the
  effective chain is Ultra -> rules.
- The regex instruction detector does not generalise (0/12 on held-out phrasings); safety does
  not depend on it - see EVAL_NOTES §6.

## [4.0.2] — 2026-11-09

### Added
- Supply-chain & CI security: `security.yml` (gitleaks secret scan, Bandit static analysis,
  pip-audit dependency audit [advisory], CycloneDX SBOM artifact) and `codeql.yml`
  (CodeQL for Python + JavaScript, weekly + on PR).
- Dependabot for pip and GitHub Actions.
- `SECURITY.md` disclosure policy and `.well-known/security.txt` (RFC 9116).
- CycloneDX SBOM attached to each GitHub release.
- README status badges (Tests, Security Scans, CodeQL, Release).

### Security
- **CWE-502:** `SequenceClassifier.load()` now uses `torch.load(weights_only=True)` with an
  explicit allowlist (sklearn scaler/imputer + numpy array/dtype reconstructors only), so a
  tampered checkpoint cannot execute code. Regression test added.
- MD5 used for leakage-eval row de-duplication is now marked `usedforsecurity=False` (B324);
  hashes are unchanged.
- Bandit `B104` (`"0.0.0.0"` placeholder IPs, not socket binds) annotated with justified
  `# nosec` comments.

## [4.0.1] — 2026-11-09

### Fixed
- CI: the live NVIDIA NIM test (`tests/test_nvidia_nim_live.py`) now **skips** when
  `NVIDIA_API_KEY` is unset (instead of `sys.exit(1)`), so the suite passes on fresh
  clones / CI without a key.

## [4.0.0] — 2026-11-09

First release of the single-author, clean-history detection core. Numbered v4.0.0 to
supersede the prior public tags (which reached v3.1).

### Added
- **Supervised OOD / zero-day signal** — isotonic-calibrated XGBoost (`1 − max calibrated
  confidence ≥ tau`), tau calibrated to a 2% false-OOD rate; same model backs `/score/flow`
  and the leave-one-class-out evaluation.
- **Layer-7 low-and-slow detector** (Slowloris / R.U.D.Y.) wired into `/score/flow`.
- **Leakage-safe evaluation** — by-capture / chronological splits, binary + per-class metrics,
  and a **shortcut-feature audit** confirming the score is real signal, not an artefact.
- **Observability** — Prometheus-compatible `/metrics` endpoint and opt-in structured JSON logs.
- **One-command demo** (`python -m src.demo`) and dataset citations (`docs/DATASETS.md`).
- Authentication on the dashboard JSON/LLM endpoints (`/api/chat`, `/api/campaigns`,
  `/api/session-detection-summary`).

### Changed
- **Fail-closed authentication (F-1 fix)** — built-in test keys are honoured only under
  `DDOS_ENV=test`; the service refuses to start in production/staging without a configured key.
- Low-and-slow concurrency threshold is configurable via `DDOS_LOWSLOW_THRESHOLD`.
- Fresh-clone CI: `DummyClassifier` fallback when model artefacts are absent, and
  artefact-dependent tests skip with a clear reason (see README "Model artifacts").

### Security
- Removed the always-valid hardcoded admin/scoring credentials from the auth path.

### Notes
- Reported detection numbers are **CIC-DDoS2019 same-dataset** (separate extraction);
  cross-dataset generalization (CIC-IDS2017 / UNSW-NB15) is planned for v5.0.0 (M6).

[4.1.0]: https://github.com/Shadowprofessor/DDOS-Attack-Detection/releases/tag/v4.1.0
[4.0.2]: https://github.com/Shadowprofessor/DDOS-Attack-Detection/releases/tag/v4.0.2
[4.0.1]: https://github.com/Shadowprofessor/DDOS-Attack-Detection/releases/tag/v4.0.1
[4.0.0]: https://github.com/Shadowprofessor/DDOS-Attack-Detection/releases/tag/v4.0.0
