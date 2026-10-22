# Contributing Guidelines

We welcome contributions to the DDoS Attack Detection & Mitigation Platform.

---

## Code of Conduct & Safety Mandate

Before contributing code, please review our core development rules in `AGENTS.md` and `PROJECT_RULES.md`:

1. **Safety First**: NEVER write or contribute code designed to launch attacks against external or real-world networks. Synthetic test traffic is strictly confined to isolated, local Docker/Mininet test harnesses directed only at containers owned by the harness.
2. **Layer 0 Approval Gate**: Automated mitigation execution is strictly gated. Detection and LLM reasoning modules propose actions; all firewall, Docker, and OpenFlow drop operations must go through human operator approval via `PendingActionManager`.
3. **Deterministic Testing**: Every new capability or bug fix must include comprehensive unit tests (`pytest`).
4. **Secret Hygiene**: Never commit API keys, tokens, or credentials. Always load from environment variables.

---

## Development Workflow

1. **Fork the Repository**:
   Create a personal fork of `https://github.com/Shadowprofessor/DDOS-Attack-Detection.git`.
2. **Create a Feature Branch**:
   ```bash
   git checkout -b feat/my-new-feature
   ```
3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
4. **Run the Test Suite**:
   ```bash
   python -m pytest tests/ -q
   ```
5. **Verify Security AST Rules**:
   ```bash
   python -m pytest tests/test_mitigation_bypass.py -v
   ```
6. **Submit a Pull Request**:
   Push your branch to your fork and open a Pull Request describing your changes, motivation, and test coverage evidence.
