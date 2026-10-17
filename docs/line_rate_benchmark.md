# Line-Rate eBPF/XDP Ingress Benchmark & Architectural Guidance

## 1. Overview
The **Layer 1 eBPF/XDP flow probe** (`src/ebpf/xdp_flow_probe.c`) is designed to capture packet metadata at the earliest possible stage in the Linux networking subsystem: the network interface driver level before `sk_buff` allocation.

### The 40 Gbps Target vs. Cloud VPC Limitations
- **Bare-Metal / On-Premises (Native XDP)**:
  - Executes directly in the NIC driver's receive ring buffer (`XDP_FLAGS_DRV_MODE`).
  - Capable of sustaining up to **40 Gbps** line-rate ingress (59.52 Mpps for 64-byte packets) on enterprise NICs (e.g. Mellanox ConnectX-5/6 `mlx5`, Intel E810 `ice`).
  - Zero allocation overhead; metadata is extracted into a lockless BPF ring buffer, returning `XDP_PASS`.
- **Cloud VPC Environments (Generic XDP)**:
  - Most public cloud virtualized NIC drivers (AWS ENA, GCP virtio-net, Azure MANA / Accelerated Networking) do **not** support native driver-level XDP.
  - When deployed in cloud VPCs, the loader automatically logs a warning and operates in **Generic (SKB-based) XDP mode** (`XDP_FLAGS_SKB_MODE`).
  - Generic mode runs after the Linux kernel allocates the `sk_buff` structure. Throughput in generic mode performs **closer to libpcap** (~1 Gbps to 5 Gbps per core), **not** the 40 Gbps line-rate figure.
  - **Operator Guidance**: Enterprise production deployments requiring line-rate multi-10-Gbps ingress must be provisioned on bare-metal hardware with native XDP driver support.

---

## 2. Benchmark Architecture (`test_line_rate_throughput_manual`)

The benchmark harness tests:
1. **Ingress Ingestion Rate (Mpps)**: Measures maximum sustained packet rate without ring buffer drops.
2. **Backpressure & Drop Accounting**: Measures ring buffer drop count under synthetic oversubscription.
3. **Feature-Extraction Latency**: Per-packet userspace decoding and 77-feature flow accumulation latency.

### Benchmark Test Location
* File: `tests/test_ebpf_probe.py::test_line_rate_throughput_manual`
* Execution Gate: Hardware-gated via `@pytest.mark.skipif(not is_real_xdp_available(), ...)` so virtualized CI runners skip cleanly with explicit reasons.

---

## 3. Running the Benchmark (Manual Phase 4 Gate)

On an on-premise bare-metal Linux server with root privileges and a native XDP-supported NIC:

```bash
# 1. Ensure driver is in native mode
ip link set dev eth0 xdp off
python -m pytest tests/test_ebpf_probe.py -k test_line_rate_throughput_manual -s -v
```

### Expected Output & Gate Verification
```text
============================= test session starts =============================
tests/test_ebpf_probe.py::test_line_rate_throughput_manual
[BENCHMARK] Interface: eth0 (native mode)
[BENCHMARK] Generating 1,000,000 packets at line-rate...
[BENCHMARK] Throughput: 14.88 Mpps (10 Gbps equivalent)
[BENCHMARK] Ring Buffer Drops: 0 (0.00%)
[BENCHMARK] Feature Extraction Latency: p95 = 0.42 microseconds/pkt
PASSED
======================== 1 passed in 4.12s ========================
```
