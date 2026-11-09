# Environment Setup & SDN Emulation Guide

This guide details the environment setup for running the SDN emulation, ML detection service, and SOC dashboard.

---

## 1. Prerequisites

### Local Python Environment (Detection, ML & Dashboard)
- **OS**: Windows, macOS, or Linux
- **Python**: 3.11+
- **Package Manager**: `pip`

```bash
pip install -r requirements.txt
```

---

## 2. SDN Emulation Setup (Mininet + Ryu)

Mininet requires Linux kernel network namespaces. You can run the emulation environment inside Ubuntu (native, WSL2, or a VirtualBox/VMware VM).

### Step 1: Install Dependencies on Ubuntu
```bash
sudo apt update
sudo apt install -y openvswitch-switch mininet python3-pip
```

### Step 2: Clone the Repository
```bash
git clone https://github.com/Shadowprofessor/DDOS-Attack-Detection.git
cd DDOS-Attack-Detection
```

### Step 3: Run the Ryu SDN Controller
Start the SDN controller with the machine learning detection and approval-gated mitigation app:
```bash
ryu-manager Codes/controller/enhanced_security_controller.py
```

### Step 4: Launch the Mininet Topology
In a separate terminal on the Linux environment:
```bash
sudo python3 Codes/mininet/topology.py
```

---

## 3. Synthetic Traffic Simulation (Isolated Sandbox)

> **Important**: Traffic generation commands must only be executed inside the isolated local Mininet sandbox directed at sandbox-internal target IPs. Never target public internet hosts.

Inside the Mininet CLI (`mininet>`):
```bash
# ICMP ping echo test
h1 ping -c 5 h2

# High-rate synthetic flow generation across sandbox hosts
h1 python3 -m scripts.traffic_generator --target 10.0.0.2 --rate 100
```

---

## 4. Running the Real-Time Scoring API & Dashboard

In your primary terminal:
```bash
# Run FastAPI scoring engine with WebSocket broadcaster
uvicorn src.api.scoring_service:app --host 0.0.0.0 --port 8000 --reload
```

Access the real-time SOC security dashboard at `http://localhost:8000`.
