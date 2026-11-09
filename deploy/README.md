# Deployment Guide — DDoS Attack Detection & Mitigation System

This directory contains production-ready deployment packaging for three target environments:
1. **Docker Compose** (`deploy/docker-compose.yml`) — multi-container local and staging environments.
2. **Kubernetes Helm Chart** (`deploy/helm/`) — cloud-native orchestration with configurable pods.
3. **Bare-Metal Systemd Services** (`deploy/systemd/`) — native single-host Linux service installation.

---

## ⚠️ Critical Deployment Caveat: Capture Mode & Feature Completeness

> ### `tc clsact` Egress Hook Deferred Past v3.0 (Host-Ingress Detection Quality Tradeoff)
> - **Files:** `src/ebpf/xdp_flow_probe.c`, `src/ebpf/loader.py`, `src/features/capture_backends/ebpf_backend.py`
> - **Decision:** Explicitly deferred past v3.0 (scheduled for v3.1 / Phase 6).
> - **Tradeoff Rationale**:
>   - `host_ingress` mode (the default deployment mode, requiring zero extra hardware) captures exclusively at the XDP driver RX layer. As a result, outbound host responses bypass XDP, capping real feature completeness at **0.7013 (54/77 features populated)** and forcing all 23 backward features (including XGBoost's #2 feature `Bwd Packets/s` at 8.67% gain and #12 `Down/Up Ratio` at 1.55% gain) to fixed zero values.
>   - Adding a `tc clsact` egress filter requires managing qdisc netlink attachments, synchronizing ingress/egress ring-buffer events across multiple CPU queues, and reconciling clock skew and out-of-order packet timing in userspace.
>   - With the Nov 15 release deadline (< 4 weeks away) and critical Phase 5 (adversarial robustness testing) and production deployment (Docker/Helm/systemd) ahead, attempting to squeeze in a kernel egress filter introduces unacceptable delivery and stability risk.
> - **Deployment Guidance**:
>   - `host_ingress` mode (default, no extra hardware) trades ~30% of backward-flow signal for zero deployment friction.
>   - `tap` mode (dedicated SPAN/TAP hardware mirror) achieves full 1.0 (77/77 feature) fidelity.

---

## Zero-Paid-Cloud Graceful Degradation Guarantee

The entire system is designed to deploy and pass health checks with **zero paid cloud subscriptions active**.
- The Cloudflare Magic Transit connector (`src/mitigation/cloud_enforcers/cloudflare.py`) defaults to proposal-only mode when `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` are unset.
- Proposed `cloudflare_scrub` actions remain inspectable and visible in the pending queue (`/actions/pending`).
- If an operator attempts to approve a Cloudflare action while credentials are unset, the system rejects execution with a clean `500 Action execution failed: Cloudflare API token not configured` response; the service itself does **not** crash or fail health checks.

---

## Architecture Overview

```
                          Internet / Clients
                                 │
                         ┌───────▼────────┐
                         │  Reverse Proxy │ (Port 80 / Nginx)
                         └───────┬────────┘
                                 │
            ┌────────────────────┴────────────────────┐
            │ HTTP & Dashboard Routes                 │ WebSocket (/ws/dashboard)
            ▼                                         ▼
┌───────────────────────┐                 ┌───────────────────────┐
│ FastAPI Scoring Svc   │                 │ Real-Time SOC Stream  │
│ Port 8000             │                 │ First-Message Auth    │
└───────────┬───────────┘                 └───────────────────────┘
            │
            ├───────────────┐
            ▼               ▼
┌───────────────────┐ ┌───────────────────┐
│ Models (CPU-safe) │ │ OpenFlow / Ryu    │ (Ports 6653 / 8080)
│ XGBoost + Ensem.  │ │ Controller        │
└───────────────────┘ └───────────────────┘
```

---

## Path 1: Docker Compose

### Prerequisites
- Docker Engine 24.0+ & Docker Compose v2.20+
- Models directory populated in `models/`

### 1. Start the Stack
```bash
# Build and start services in the background
docker compose -f deploy/docker-compose.yml up -d
```

### 2. Verify Stack Status
```bash
docker compose -f deploy/docker-compose.yml ps
```

### 3. Verify Health Checks & Endpoints
```bash
# 1. Unauthenticated Health Check (Expect 200 OK)
curl -i http://localhost:80/health

# Response:
# HTTP/1.1 200 OK
# {"status":"ok","models_loaded":true}

# 2. Authenticated Pending Actions Endpoint (Expect 200 OK with dev or configured key)
# Note: If DDOS_API_KEYS was left blank, check container logs for the auto-generated dev key:
#   docker compose -f deploy/docker-compose.yml logs scoring_service | grep "AUTO-GENERATED DEV API KEY"
API_KEY="<your-api-key>"
curl -i -H "X-API-Key: ${API_KEY}" http://localhost:80/actions/pending

# Response:
# HTTP/1.1 200 OK
# {"pending_actions":[],"count":0}

# 3. WebSocket Dashboard Handshake Verification (First-Message Auth)
# Prompt 7 requires sending {"type": "auth", "api_key": "<key>"} within 5.0 seconds.
# Using python to verify immediate rejection on an invalid key:
python -c '
import asyncio, websockets, json

async def test():
    uri = "ws://localhost:80/ws/dashboard"
    try:
        async with websockets.connect(uri) as ws:
            # Send invalid credentials
            await ws.send(json.dumps({"type": "auth", "api_key": "invalid-key"}))
            response = await ws.recv()
            print("Received response:", response)
    except websockets.exceptions.ConnectionClosed as e:
        print(f"Connection closed as expected: code={e.code}, reason={e.reason}")

asyncio.run(test())
'
```

### 4. Stop the Stack
```bash
docker compose -f deploy/docker-compose.yml down
```

---

## Path 2: Kubernetes Helm Chart

### Prerequisites
- Kubernetes cluster v1.26+
- Helm v3.10+
- Ingress controller (e.g. `ingress-nginx`) if exposing externally

### 1. Inspect & Customize Chart Values
Review `deploy/helm/values.yaml`. To supply credentials securely:
```bash
helm install ddos-defense ./deploy/helm \
  --set secrets.apiKeys="operator-key-1,operator-key-2" \
  --set secrets.adminKeys="admin-super-key" \
  --set scoringService.replicaCount=2
```

### 2. Verify Pod Health & Rollout
```bash
kubectl get pods -l app.kubernetes.io/name=ddos-defense
kubectl rollout status deployment/ddos-defense-scoring
```

### 3. Verify Health Check
```bash
# Forward port from reverse proxy or scoring service
kubectl port-forward svc/ddos-defense-reverse-proxy 8080:80

# Verify health
curl -i http://localhost:8080/health
```

---

## Path 3: Bare-Metal Systemd Services

### Prerequisites
- Linux host (Ubuntu 22.04 LTS, Debian 12, or RHEL 9)
- Python 3.11+
- Systemd & Nginx

### 1. Run the Automated Installer
```bash
sudo bash deploy/systemd/install.sh
```

### 2. Configure Environment Secrets
Edit `/etc/ddos-defense/ddos-defense.env`:
```ini
DDOS_ENV=production
DDOS_API_KEYS=your-production-api-key
DDOS_ADMIN_KEYS=your-production-admin-key
```

### 3. Start and Enable Services
```bash
sudo systemctl enable --now ddos-scoring.service
sudo systemctl enable --now ddos-controller.service

# Check status
sudo systemctl status ddos-scoring.service
sudo systemctl status ddos-controller.service
```

### 4. Verify Health
```bash
curl -i http://localhost:80/health
curl -i -H "X-API-Key: your-production-api-key" http://localhost:80/actions/pending
```
