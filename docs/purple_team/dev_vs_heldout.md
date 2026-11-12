# Coverage: DEV vs HELD-OUT (v5.3.0)

| Scenario | Expected | DEV (runs 2+3: tuned on) | HELD-OUT (run4: never tuned on) |
|---|---|---|---|
| `benign_baseline` | no incident | **clean** · none · Benign / insufficient evidence · not detected | **clean** · none · Benign / insufficient evidence · not detected |
| `dns_reflection_sim` | dns_amplification via L1+L2+L3 | **detected** · L1, L2, OOD, L3 · DNS reflection-amplification · 0.9 s | **detected** · L1, L2, OOD, L3 · DNS reflection-amplification · 1.2 s |
| `flash_crowd` | no incident | **clean** · none · Benign / insufficient evidence · not detected | **clean** · none · Benign / insufficient evidence · not detected |
| `http_low_and_slow` | l7_low_and_slow via L1+L3 | **detected** · L1, L2, L3 · Slowloris / low-and-slow HTTP (L7) · 117.3 s | **detected** · L1, L2, L3 · Slowloris / low-and-slow HTTP (L7) · -0.9 s |
| `icmp_flood` | other via L1+L3 | **detected** · L1, L2, L3 · ICMP flood · 55.8 s | **detected** · L1, L2, L3 · ICMP flood · -0.9 s |
| `land_attack` | other via L1 | **detected** · L1, L2, OOD, L3 · LAND attack (source IP equals destination IP) · 60.8 s | **detected** · L1, L2, L3 · LAND attack (source IP equals destination IP) · 61.1 s |
| `novel_ood_mix` | zero_day_ood via OOD+L3 | **detected** · L1, L2, OOD, L3 · Unclassified multi-protocol flood (possible zero-day / novel) · 1.4 s | **detected** · L1, L2, OOD, L3 · Unclassified multi-protocol flood (possible zero-day / novel) · 1.3 s |
| `ntp_reflection_sim` | udp_reflection_amplification via L1+L2+L3 | **detected** · L1, L2, OOD, L3 · UDP reflection-amplification (NTP) · 1.2 s | **detected** · L1, L2, OOD, L3 · UDP reflection-amplification (NTP) · 1.3 s |
| `syn_flood` | syn_flood via L1+L2+L3 | **detected** · L1, L2, OOD, L3 · TCP SYN flood · 1.0 s | **detected** · L1, L2, L3 · TCP SYN flood · 1.4 s |
| `tcp_ack_flood` | other via L1 | **detected** · L1, L2, OOD, L3 · TCP ACK flood · 1.2 s | **detected** · L1, L2, OOD, L3 · TCP ACK flood · 1.3 s |
| `tcp_rst_flood` | other via L1 | **detected** · L1, L2, OOD, L3 · TCP RST flood · 1.5 s | **detected** · L1, L2, L3 · TCP RST flood · 1.4 s |
| `udp_flood` | udp_reflection_amplification via L1+L2+L3 | **detected** · L1, L2, OOD, L3 · UDP flood · 0.9 s | **detected** · L1, L2, OOD, L3 · UDP flood · 1.3 s |

DEV outcomes: {'clean': 2, 'detected': 10}; HELD-OUT outcomes: {'clean': 2, 'detected': 10}.
Model fingerprint DEV `d953fc29e14f`, HELD-OUT `d953fc29e14f`.
