| Scenario | Outcome | Expected | Observed layers | L3 family | Flagged flows | MTTD (s) | MTTD + 60 s export |
|---|---|---|---|---|---:|---:|---:|
| `benign_baseline` | **false_positive** | no incident | L1 | other | 13/413 (3%) | 0.6 | 60.6 |
| `dns_reflection_sim` | **partial** | dns_amplification via L1+L2+L3 | L1, L2, OOD, L3 | udp_reflection_amplification | 33183/33885 (98%) | 0.9 | 60.9 |
| `flash_crowd` | **false_positive** | no incident | L1 | other | 229/557 (41%) | 0.5 | 60.5 |
| `http_low_and_slow` | **detected** | l7_low_and_slow via L1+L3 | L1, L3 | l7_low_and_slow | 300/300 (100%) | 117.3 | 177.3 |
| `novel_ood_mix` | **partial** | zero_day_ood via OOD+L3 | L1, L2, OOD | other | 31065/31065 (100%) | 1.4 | 61.4 |
| `ntp_reflection_sim` | **detected** | udp_reflection_amplification via L1+L2+L3 | L1, L2, OOD, L3 | udp_reflection_amplification | 33882/33885 (100%) | 1.2 | 61.2 |
| `syn_flood` | **partial** | syn_flood via L1+L2+L3 | L1, OOD, L3 | l7_low_and_slow | 34842/34843 (100%) | 1.0 | 61.0 |
| `udp_flood` | **detected** | udp_reflection_amplification via L1+L2+L3 | L1, L2, OOD, L3 | udp_reflection_amplification | 85579/86242 (99%) | 0.9 | 60.9 |

Containment probe to 192.0.2.1 (TEST-NET-1) with a NAT path deliberately open: nftables drops 0 → 3, packets seen on `eth0`: 0 → **contained**.
