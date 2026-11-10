# Threat hunts (v4.7.0)

Two hypothesis-driven hunts aimed at gaps the platform has **by design**: per-source L1 thresholds
miss spread-out attacks, and the per-flow ML judges flows one at a time. Each hunt produced a rule
(`src/hunt/rules.py`) with positive and negative tests (`tests/test_hunt_rules.py`, 11). Each was
then executed over the real v4.6.1 lab flows (`python -m src.hunt.run_lab_hunt data/lab_runs/run2`;
results in [`results.json`](results.json)).

## H1: low-rate distributed reflection

**Hypothesis.** An attacker spreads a reflection/amplification attack across many reflectors so
that *each* stays below per-source thresholds, while together they flood one victim from
amplification service ports (DNS 53, NTP 123, LDAP 389, SSDP 1900, memcached 11211, …).

**Query (rule `H1_low_rate_distributed_reflection`).** Per victim, per 60 s window, over UDP flows
whose **source** port is an amplification service: count distinct reflectors and total pps. Fire when
there are ≥ 50 reflectors, total ≥ 200 pps, and **every** reflector ≤ 20 pps.

**Tests.** Fires on 200 reflectors × 5 pps. Does not fire on: one loud reflector (left to L1),
100 DNS servers at 0.5 pps (normal resolver traffic), non-service source ports, or a mix with
one loud source.

**Result on the lab data.** **No findings in any of the 8 scenarios (~221k flows).** That is the
expected answer: the lab's NTP/DNS reflection used a single high-rate reflector (`10.99.0.30`,
source port 123/53), which is L1's job and is detected there. Inputs were checked to be real, not
blind: the reflection flows do carry source port 123/53. *Hypothesis not confirmed in this data.*
A positive in-lab validation needs a ≥ 50-reflector scenario, which v4.6.1's scope caps did not
include.

## H2: distributed slow-read L7 abuse

**Hypothesis.** Many clients each hold a long HTTP connection, advertise a tiny TCP receive window,
and drain the response slowly. The server's send buffers and workers are tied up, yet no single
source is noisy. The existing low-and-slow detector looks at the client's *sending* rate, so a
slow *reader* that sent a complete request can slip past it.

**Query (rule `H2_distributed_slow_read`).** Per victim: count distinct sources with TCP flows to
80/443/8080/8443 that are ≥ 20 s long, have an initial client window ≤ 1,024 bytes
(`Init Fwd Win Bytes`) and server→client throughput ≤ 200 B/s. Fire at ≥ 10 sources.

**Tests.** Fires on 15 slow readers. Does not fire on: normal windows, short or fast downloads,
< 10 sources, or an unknown window.

**Result on the lab data.** **No findings.** The lab had no slow-read clients. The Slowloris
scenario starves the server by sending slowly, not reading slowly, and is caught by the
low-and-slow detector (v4.6.1). The input is populated: flash-crowd clients advertise 42,340 B
windows, so H2 correctly stays quiet on a flash crowd. *Hypothesis not confirmed in this data.*

## What this means

Both rules are in place and tested, and neither fires on the legitimate surge (flash crowd) that
the L1 thresholds false-positive on. Neither has been validated on real positive traffic yet.
Next step: add a many-reflector and a slow-read scenario to the lab library, then re-run.
