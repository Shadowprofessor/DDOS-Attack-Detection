# Purple-team lab (v4.6.0: safety layer + scenario library)

**v4.6.0 sends no traffic.** It ships the safety layer, the scenario catalogue and a mock runner,
all tested in CI. Real traffic inside Mininet on WSL2 (v4.6.1) needs the owner's explicit approval
**before any traffic-generation code is written**.

## Safety model (enforced in code: `lab/safety.py`)

| Control | Rule | Test (`tests/test_lab_safety.py`) |
|---|---|---|
| Scope file | `lab/lab_scope.yaml` is validated on load. Allowed networks must be IPv4 private ranges no larger than /16 and never loopback / link-local / multicast / reserved. Every host role must be inside them. | `TestScopeValidation` |
| Targets | Public IPv4/IPv6 (e.g. 8.8.8.8, 1.1.1.1, 2606:4700:4700::1111) refused; private-but-not-allowlisted (10.0.0.4, 192.168.1.10, fd00::1) refused; loopback, link-local, multicast and unspecified refused. | `TestTargets` |
| Caps | packets/s ≤ `max_pps` (2,000), duration ≤ `max_duration_s` (120 s), concurrent scenarios ≤ `max_concurrent` (1). | `TestCaps` |
| Kill switch | `lab/KILL` file, `DDOS_LAB_KILL=1`, or `KillSwitch.trip()` (signal hook). It is checked before start **and before every tick**, so a running scenario stops within one tick. | `test_kill_switch_stops_within_one_tick`, `test_tripped_switch_blocks_start` |
| Environment | Refuses unless **WSL2** (`/proc/version`) **and Mininet** (`mn` on PATH and an `hN-ethX` interface) are detected. CI therefore always gets the refusal path. | `test_refuses_outside_lab`, `test_runner_refuses_outside_lab_before_anything` |
| No traffic code | AST scan: nothing in `lab/` imports `scapy`, `socket`, `subprocess`, `requests`, `httpx`, `urllib`, `http`, `asyncio`, `ssl`, `ctypes`, `multiprocessing`, or calls `system`/`popen`/`exec*`/`send*`/`connect`. | `test_lab_package_contains_no_traffic_code` |

Planned for v4.6.1 (after approval): nftables **egress-drop** rules on the lab host, so anything from
the lab subnet toward a non-lab interface is dropped. A lab-only test (`@pytest.mark.lab`, skipped in
CI) proves a lab packet aimed at a real interface is dropped.

## Scenario library (`lab/scenarios/*.yaml`, schema in `lab/library.py`)

Descriptive only: protocol, rate, duration, source and target *roles* (resolved to lab addresses by
the scope), expected detection. The schema forbids extra fields, so a scenario cannot carry a
command or a raw address.

| Scenario | Attack | ATT&CK | Expected incident / family | Expected layers | MTTD budget |
|---|---|---|---|---|---|
| `benign_baseline` | no | — | none | — | — |
| `flash_crowd` | no | — | **none** (must not alert) | — | — |
| `syn_flood` | yes | T1499.001, T1498.001 | `syn_flood` | L1, L2, L3 | 30 s |
| `udp_flood` | yes | T1498.001 | `udp_reflection_amplification` | L1, L2, L3 | 30 s |
| `ntp_reflection_sim` | yes | T1498.002 | `udp_reflection_amplification` | L1, L2, L3 | 30 s |
| `dns_reflection_sim` | yes | T1498.002 | `dns_amplification` | L1, L2, L3 | 30 s |
| `http_low_and_slow` | yes | T1499.002 | `l7_low_and_slow` | L1, L3 | 90 s |
| `novel_ood_mix` | yes | T1498 | `zero_day_ood` | OOD, L3 | 60 s |

Reflection scenarios use a **simulated reflector inside the lab** (`reflector` role). No real NTP or
DNS servers are involved.

## Mock runner (`lab/runner.py`)

`MockRunner.run()` applies every check above. It then produces per-tick *descriptions* of the
traffic, with no packets, re-checking the kill switch before each tick. `to_aggregate()` turns a run
into a synthetic `IncidentAggregate` that can be replayed through L1 → L2 → rule-based L3.

`TestMockPipelineWiring` replays three scenarios and checks they land in their expected incident
family. **That is a wiring check, not detection evidence**: the aggregate is derived from the
scenario's own description. Measured MTTD, false positives and the coverage matrix need real lab
traffic (v4.6.1).
