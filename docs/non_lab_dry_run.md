# Non-Lab Topology Dry Run

## Status: NOT EXECUTED — ENVIRONMENT UNAVAILABLE

**Date:** 2026-10-18
**Prompt:** 11b
**Author:** Automated assessment via development environment inspection

---

## Environment Assessment (Step 1)

The following infrastructure checks were performed to determine whether a real non-lab
deployment could be executed:

### 1. Cloud VPC Account (AWS / GCP / Azure)
- **Result: NONE AVAILABLE**
- No cloud CLI tools (`aws`, `gcloud`, `az`) are installed on this machine.
- No cloud-related environment variables (`AWS_ACCESS_KEY_ID`, `GCP_PROJECT`,
  `AZURE_SUBSCRIPTION_ID`, etc.) are set.
- No cloud provider SDK or credential file is present.

### 2. Second Physical Network / Remote Host
- **Result: NONE AVAILABLE**
- The only active network interface is university Wi-Fi (`172.19.22.132` on
  `niituniversity.in`, subnet `255.255.248.0`, gateway `172.19.16.1`).
- Two Ethernet adapters (`Ethernet 2`, `Ethernet 3`) show APIPA addresses
  (`169.254.*`) — no DHCP, no link, no routable connectivity.
- No SSH keys, VPS credentials, or remote host configuration is present.
- No second physical machine, home server, or external VPS is reachable from this
  development environment.

### 3. Docker Desktop Daemon Status
- **Result: INACTIVE**
- Docker CLI v29.5.3 is installed with Docker Compose v5.1.4.
- Docker Desktop daemon is not running: `docker info` returns
  `failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine`.
- Even a local Docker Compose smoke test (`docker compose up`) cannot be executed
  in this state.

---

## What a Real Dry Run Must Test (Checklist for Future Execution)

When a non-lab environment becomes available, the following four checks must be
executed and their results recorded with real output (not prose summaries):

### Check 1: Scoring Service Health on Non-Lab Host
- Deploy the scoring service using one of the three Prompt 11 packaging paths
  (Docker Compose recommended for fastest turnaround).
- Verify `GET /health` returns HTTP 200 with `{"status": "ok", "models_loaded": true}`
  on a host that is NOT the development/lab machine.
- Record: HTTP response headers, status code, body.

### Check 2: Real Traffic Capture via libpcap Backend
- Run `capture_backends/libpcap_backend.py` on the non-lab host's real network
  interface (not a loopback or synthetic generator).
- Confirm it produces non-degenerate 77-feature flow vectors from actual network
  traffic (not synthetic packets from scapy/hping3 pointed at localhost).
- Record: Interface name, sample flow feature vector (first 10 features), total
  flows captured in a 60-second window, and whether backward features are populated
  (they should be if using libpcap on a real interface, unlike eBPF host_ingress).

### Check 3: Cross-Network API and WebSocket Access
- From a different machine (or at minimum, a different network segment), access:
  - `GET /actions/pending` with a valid `X-API-Key` header — expect HTTP 200.
  - `ws://host:port/ws/dashboard` — send `{"type": "auth", "api_key": "<key>"}` and
    confirm the WebSocket handshake succeeds.
  - Send an invalid key and confirm immediate connection closure (Prompt 7's
    first-message auth pattern).
- This is the check most likely to break outside a lab environment due to:
  - Firewall rules blocking port 8000 or WebSocket upgrade headers.
  - NAT/proxy stripping or failing to forward `X-API-Key` or `Upgrade` headers.
  - Corporate/university network policies blocking non-standard ports.
- Record: Source IP, destination IP, any firewall/NAT between them, full HTTP
  response (including headers), WebSocket connection trace.

### Check 4: Synthetic Attack → Alert → PendingAction Pipeline
- Generate a clearly-labeled, short synthetic attack against the deployed system
  (e.g., `hping3` SYN flood from a second container or co-located test script
  targeting ONLY the deployment's own IP — never a third party's infrastructure).
- Confirm:
  - An alert reaches the real-time dashboard via the WebSocket stream.
  - A `PendingAction` is created and visible via `GET /actions/pending`.
  - The action's `status` is `PENDING` (not auto-executed — per AGENTS.md rules).
- Record: Attack command used, alert JSON from WebSocket, PendingAction JSON from
  API response.

### Required Infrastructure for Execution
At minimum, one of the following:
- **Cloud VPC** (AWS free-tier EC2 t2.micro, GCP e2-micro, or Azure B1s): A single
  Linux VM with Docker installed, accessible via SSH. Estimated cost: $0 (free tier)
  to ~$5/month.
- **VPS** (DigitalOcean Droplet, Linode, Vultr, Hetzner): A $5-10/month Linux VPS
  with Docker and 2GB RAM.
- **Second Physical Machine**: Any Linux machine on a different network segment
  (home LAN, friend's machine, university server with Docker access).
- **University Lab Server**: If NIIT University provides student access to a Linux
  server or VM cluster with Docker permissions, this would be the zero-cost option.

---

## Impact on v3.0 Release Claims

This dry run was defined as a Phase 5 gate criterion to prevent shipping a "Production
Hardened" release that has only been tested in the same lab/CI environment where it was
developed.

**Without execution of this dry run, v3.0 release notes must state:**

> "Verified in lab/CI environments (local development machine, Mininet/SDN simulation,
> synthetic/historical datasets, and Docker Compose config validation). Not yet verified
> on a non-lab network topology. Cross-network deployment (firewalls, NAT, proxy header
> forwarding) and real-traffic capture on production interfaces have not been exercised."

This is the same honesty standard applied to:
- The `tc clsact` egress hook deferral (KNOWN_ISSUES.md §11)
- The hardware line-rate benchmark rename (KNOWN_ISSUES.md §12)
