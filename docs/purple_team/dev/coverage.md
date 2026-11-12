| Scenario | Outcome | Expected | Observed layers | L3 family | Flagged flows | MTTD (s) | MTTD + 60 s export |
|---|---|---|---|---|---:|---:|---:|
| `benign_baseline` | **clean** | no incident | none | — | 0/413 (0%) | — | — |
| `dns_reflection_sim` | **detected** | dns_amplification via L1+L2+L3 | L1, L2, OOD, L3 | dns_amplification | 33694/33885 (99%) | 0.9 | 60.9 |
| `flash_crowd` | **clean** | no incident | none | — | 0/557 (0%) | — | — |
| `http_low_and_slow` | **detected** | l7_low_and_slow via L1+L3 | L1, L2, L3 | l7_low_and_slow | 300/300 (100%) | 117.3 | 177.3 |
| `novel_ood_mix` | **detected** | zero_day_ood via OOD+L3 | L1, L2, OOD, L3 | zero_day_ood | 30874/31065 (99%) | 1.4 | 61.4 |
| `ntp_reflection_sim` | **detected** | udp_reflection_amplification via L1+L2+L3 | L1, L2, OOD, L3 | udp_reflection_amplification | 33694/33885 (99%) | 1.2 | 61.2 |
| `syn_flood` | **detected** | syn_flood via L1+L2+L3 | L1, L2, OOD, L3 | syn_flood | 34604/34843 (99%) | 1.0 | 61.0 |
| `udp_flood` | **detected** | udp_reflection_amplification via L1+L2+L3 | L1, L2, OOD, L3 | udp_reflection_amplification | 85242/86242 (99%) | 0.9 | 60.9 |
| `icmp_flood` | **detected** | other via L1+L3 | L1, L2, L3 | other | 20/20 (100%) | 55.8 | 115.8 |
| `tcp_ack_flood` | **detected** | other via L1 | L1, L2, OOD, L3 | other | 30803/31278 (98%) | 1.2 | 61.2 |
| `tcp_rst_flood` | **detected** | other via L1 | L1, L2, OOD, L3 | other | 58289/59263 (98%) | 1.5 | 61.5 |
| `land_attack` | **detected** | other via L1 | L1, L2, OOD, L3 | other | 1/1 (100%) | 60.8 | 120.8 |

Containment probe to 192.0.2.1 (TEST-NET-1) with a NAT path deliberately open: nftables drops 0 → 3, packets seen on `eth0`: 0 → **contained**.
