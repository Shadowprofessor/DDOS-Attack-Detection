| Scenario | Outcome | Expected | Observed layers | L3 family | Flagged flows | MTTD (s) | MTTD + 60 s export |
|---|---|---|---|---|---:|---:|---:|
| `benign_baseline` | **clean** | no incident | none | — | 0/371 (0%) | — | — |
| `dns_reflection_sim` | **detected** | dns_amplification via L1+L2+L3 | L1, L2, OOD, L3 | dns_amplification | 33532/33723 (99%) | 1.2 | 61.2 |
| `flash_crowd` | **clean** | no incident | none | — | 0/322 (0%) | — | — |
| `http_low_and_slow` | **detected** | l7_low_and_slow via L1+L3 | L1, L2, L3 | l7_low_and_slow | 303/303 (100%) | -0.9 | 59.1 |
| `icmp_flood` | **detected** | other via L1+L3 | L1, L2, L3 | other | 74/74 (100%) | -0.9 | 59.1 |
| `land_attack` | **detected** | other via L1 | L1, L2, L3 | other | 1/1 (100%) | 61.1 | 121.1 |
| `novel_ood_mix` | **detected** | zero_day_ood via OOD+L3 | L1, L2, OOD, L3 | zero_day_ood | 26796/27002 (99%) | 1.3 | 61.3 |
| `ntp_reflection_sim` | **detected** | udp_reflection_amplification via L1+L2+L3 | L1, L2, OOD, L3 | udp_reflection_amplification | 33105/33296 (99%) | 1.3 | 61.3 |
| `syn_flood` | **detected** | syn_flood via L1+L2+L3 | L1, L2, L3 | syn_flood | 26656/26891 (99%) | 1.4 | 61.4 |
| `tcp_ack_flood` | **detected** | other via L1 | L1, L2, OOD, L3 | other | 44988/45471 (99%) | 1.3 | 61.3 |
| `tcp_rst_flood` | **detected** | other via L1 | L1, L2, L3 | other | 72257/73235 (99%) | 1.4 | 61.4 |
| `udp_flood` | **detected** | udp_reflection_amplification via L1+L2+L3 | L1, L2, OOD, L3 | udp_reflection_amplification | 67112/68108 (99%) | 1.3 | 61.3 |

Containment probe to 192.0.2.1 (TEST-NET-1) with a NAT path deliberately open: nftables drops 0 → 3, packets seen on `eth0`: 0 → **contained**.
