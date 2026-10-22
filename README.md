# Advanced Multi-Layer DDoS Attack Detection, Attacker Forensics & Intelligent Mitigation Platform

[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests: 243+ Passing](https://img.shields.io/badge/Tests-243%2B%20Passing-brightgreen.svg)](tests/)
[![Security: Gated Mitigation](https://img.shields.io/badge/Security-Approval%20Gated-orange.svg)](src/mitigation/)

An advanced, defense-in-depth Distributed Denial of Service (DDoS) detection, attacker forensics, and intelligent mitigation platform designed for Software-Defined Networks (SDN) and modern cloud edge infrastructures. All detection code is strictly defensive; attack-traffic generation is restricted to isolated local test harnesses targeting owned containers only. Mitigation actions require explicit human approval — no automatic execution.

---

## 🏛️ System Architecture (4-Layer Defense)

The platform operates across four coordinated layers, forming a defense-in-depth pipeline:

```text
       Incoming Raw Traffic / PCAP / Network Stream
                           │
                           ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Layer 1: Telemetry & Ingress Packet Sanity Filter            │
 │ • RFC-compliant TCP flag validation (SYN+FIN, NULL, XMAS, PSH/URG without ACK)    │
 │ • Packet boundary checks and size anomaly guards             │
 │ • IP fragmentation evasion detection (TINY_MF, FRAGMENT_FLOOD, IP_FRAGMENT) │
 │ • 77-feature CICFlowMeter flow representation                │
 └─────────────────────────────────────────────────────────────┘
                           │ Validated Flow Features
                           ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Layer 2: Fast Machine Learning Classifiers                  │
 │ • XGBoost & Random Forest / ExtraTrees multi-class attack classifiers │
 │ • Asymmetric host-ingress telemetry adaptation (feature completeness calibration) │
 │ • Confidence scoring with degraded-input handling           │
 │ • BiLSTM SequenceClassifier with pseudo-temporal windows (optional) │
 └─────────────────────────────────────────────────────────────┘
                           │ High-Confidence Alerts & Anomalies
                           ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Layer 3: Generative LLM Reasoning Agent (Nemotron 3 Ultra)   │
 │ • Multi-flow alert correlation & attacker attribution       │
 │ • False-positive suppression & threat intelligence lookup   │
 │ • Contextual mitigation strategy recommendation             │
 │ • Structured JSON output: explanation, severity, proposed_action, requires_human_approval │
 └─────────────────────────────────────────────────────────────┘
                           │ Proposed Mitigation Actions
                           ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Layer 0: Mitigation Engine & Operator Approval Gate         │
 │ • PendingActionManager: Strict Human-in-the-Loop review     │
 │ • All actions auto_execute=False; persisted to pending_actions.json │
 │ • Multi-target enforcers: OpenFlow, IPSet, iptables, Docker container isolator, Cloudflare, AWS Shield │
 │ • Zero unapproved automated execution (AST enforced — code audit verified) │
 │ • Approval gate: CLI command, dashboard button, or admin API triggers human approval │
 └─────────────────────────────────────────────────────────────┘
```

---

## 🌟 Key Capabilities

### 1. Layer 1 Ingress Sanity Filtering (`src/features/packet_sanity_filter.py`)
- **RFC Protocol Conformance**: Intercepts contradictory TCP flags (SYN+FIN, SYN+RST, NULL scans, XMAS, PSH/URG without ACK).
- **Packet Boundary Checks**: Verifies header lengths against total payload sizes and enforces sub-minimum payload thresholds.
- **Fragmentation Evasion Interception**:
  - `IP_FRAGMENT`: Detects non-first IP fragments.
  - `TINY_MF_FRAGMENT`: Catches More-Fragments (`MF=1`) datagrams smaller than 576 bytes (RFC 791 minimum reassembly buffer limit) used in evasion attacks.
  - `FRAGMENT_FLOOD`: Stateful sliding-window tracker identifying fragment surges exceeding 50 fragments/sec per flow key.

### 2. Layer 2 Machine Learning Ensemble (`src/models/ensemble.py`)
- **Dual-Model Decision Tree Ensemble**: Combines tuned XGBoost and Random Forest classifiers trained on bidirectional PCAP and benchmark flow datasets.
- **Degraded Input Calibration**: Accommodates asymmetric single-interface telemetry (e.g., eBPF ingress taps where 23 backward-looking features are unobserved) by dampening confidence scores and tagging alerts with `feature_completeness`.
- **SequenceClassifier (BiLSTM)**: Optional secondary model for temporal flow analysis, with documented synthetic-windowing caveat.

### 3. Layer 3 AI Security Analyst (`src/agent/nemotron_agent.py`)
- Powered by **NVIDIA Nemotron 3 Ultra** via NVIDIA NIM / OpenRouter APIs.
- Triages security alerts, correlates distributed spoofed sources, cross-references threat scores, and generates human-readable incident summaries with actionable mitigation recommendations.
- Implements strict fallback heuristics when API quotas or offline constraints apply.

### 4. Non-Bypassable Layer 0 Mitigation Engine (`src/mitigation/`)
- **Absolute Approval Gate**: No model prediction or LLM response can directly modify firewall tables or drop packets. All actions must be queued in `PendingActionManager` for explicit operator approval.
- **Pluggable Enforcers**:
  - **SDN Controller**: Injects OpenFlow 1.3 `OFPFC_ADD` drop flow-mods to edge switches.
  - **Linux IPSet & iptables**: Generates atomic kernel drop rules for volumetric floods.
  - **Docker Sandbox Enforcer**: Disconnects or rate-limits compromised containers in test topologies.
  - **Cloud Scrubbing Adapters**: Proposes IP access rules for Cloudflare and AWS Shield APIs.

### 5. Attacker Forensics Utilities (`Codes/security/`)
- **Attacker Profiling (`attacker_profiler.py`)**: Scores attacker IPs (0–100) based on packet rate, target spread, and payload ratio.
- **GeoIP Traceback (`geo_locator.py`)**: Resolves attacker IPs to country, city, ISP, and ASN metadata for both public IPs and Mininet local subnets.
- **Attack Vector Classification (`attack_type_classifier.py`)**: Classifies detected attacks into SYN Flood, ICMP Echo Flood, UDP Amplification, LAND Attack, or Volumetric DDoS categories.
- **Forensic Incident Logger (`forensics_logger.py`)**: Writes structured JSON incident reports per attack event for security audits and post-mortem analysis.
- **Dynamic Threat Intelligence (`threat_intelligence.py`)**: Maintains a live IP blacklist/whitelist with automatic block expiration for adaptive response.
- **AI Threat Analyzer (`ai_threat_analyzer.py`)**: Lightweight local threat scoring module used as offline fallback when the Nemotron LLM agent is unavailable.
- **Docker Sandbox Enforcer (`docker_enforcer.py`)**: Disconnects or rate-limits compromised containers within local test harnesses; queued through the Layer 0 approval gate.

### 6. Real-Time SOC Command Dashboard (`src/web/realtime_dashboard/`)
- Fast, asynchronous web UI backed by FastAPI and WebSockets.
- Live attack telemetry feed with `[DEGRADED INPUT]` flags, dynamic threat score metrics (0–100), attacker geo-traceback, and one-click operator mitigation authorization.

---

## 🚀 Quickstart

### Prerequisites
- Python 3.11+
- Virtual environment tool (`venv` or `conda`)
- (Optional for SDN Emulation) Ubuntu Linux with Mininet & Ryu installed

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Shadowprofessor/DDOS-Attack-Detection.git
   cd DDOS-Attack-Detection
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   # On Linux / macOS:
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

---

## 🛠️ Usage

### 1. Launching the Real-Time Scoring Service & SOC Dashboard
Start the FastAPI server:
```bash
uvicorn src.api.scoring_service:app --host 0.0.0.0 --port 8000 --reload
```
Navigate to `http://localhost:8000` to open the SOC Command Dashboard.

### 2. Evaluating Model Ensembles on Live / Synthetic Flows
Test flow batches against the ML ensemble:
```bash
python run_full_simulation.py
```

### 3. Running Mininet & Ryu SDN Emulation (Linux)
On an Ubuntu environment with Mininet:
```bash
# Terminal 1: Start the controller
ryu-manager Codes/controller/enhanced_security_controller.py

# Terminal 2: Launch the Mininet network topology
sudo python3 Codes/mininet/topology.py
```

---

## 🧪 Testing & Validation

The codebase includes an extensive automated test suite covering unit tests, integration paths, adversarial robustness checks, and AST security audits:

```bash
# Run the complete test suite (243+ tests)
python -m pytest tests/ -q

# Run structural packet sanity filter tests
python -m pytest tests/test_packet_sanity_filter.py -v

# Run IP fragmentation evasion tests
python -m pytest tests/test_packet_sanity_filter.py -k fragmentation_evasion -v

# Run the strict AST mitigation approval gate safety audit
python -m pytest tests/test_mitigation_bypass.py -v
```

---

## 🔒 Security & Safety Mandate

1. **Defense-Only Policy**: This repository contains strictly defensive detection, feature extraction, and mitigation code. Attack traffic generation scripts are restricted to synthetic, isolated local test harnesses targeting local containers only.
2. **Mandatory Approval Gate**: All destructive actions (IP blocking, rule injection, container termination) require human confirmation via CLI or the SOC dashboard.
3. **No Hardcoded Secrets**: All API tokens (OpenRouter, NVIDIA NIM, Cloudflare) are loaded strictly from environment variables or local `.env` configurations.
4. **AST Safety Audit**: Static code audit (`tests/test_mitigation_bypass.py`) confirms `_execute_action` is ONLY called inside `PendingActionManager.approve()` — no hidden call sites exist in `src/api` or `src/mitigation`.

---

## 📁 Repository Structure

```text
DDOS-Attack-Detection/
├── src/
│   ├── features/           # Layer 1 packet sanity filter & flow extractor
│   ├── models/             # Layer 2 ML ensemble (XGBoost, Random Forest, BiLSTM)
│   ├── agent/              # Layer 3 Nemotron 3 Ultra LLM reasoning agent
│   ├── mitigation/         # Layer 0 approval gate & pluggable enforcers
│   ├── api/                # FastAPI scoring service & WebSocket feeds
│   └── web/                # Real-time SOC dashboard interface
├── tests/                  # Pytest automated test suite (243+ tests)
├── models/                 # Model artifacts & adversarial evaluation reports
├── Codes/                  # SDN Controller & Mininet emulation scripts
├── docs/                   # System architecture, datasets, and runbooks
├── requirements.txt        # Python dependencies
├── README.md               # Main project documentation
└── LICENSE                 # MIT License — see LICENSE file for details
```

---

## 👤 Author & Maintainer

- **Sachit Sharma** ([@Shadowprofessor](https://github.com/Shadowprofessor))

---

## 🙏 Origin & Attribution

This project originated from [chiragbiradar/DDoS-Attack-Detection-and-Mitigation-using-Machine-Learning](https://github.com/chiragbiradar/DDoS-Attack-Detection-and-Mitigation-using-Machine-Learning), with original contributions from Akash Kumar, Apoorv Bagal, and Abhishek Ray. It has since been substantially extended with:
- A non-bypassable, approval-gated mitigation engine (Layer 0)
- Adversarially-hardened packet sanity filtering with fragmentation evasion detection (Layer 1)
- An LLM-based threat triage agent using NVIDIA Nemotron (Layer 3)
- A real-time FastAPI/WebSocket SOC dashboard
- A 243-test automated verification suite with AST-based security auditing

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.