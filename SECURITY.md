# Security policy

This is a defensive research project (DDoS detection and human-approved response). Reports about
weaknesses in **this project's code** are welcome.

## Supported versions

Only the latest release on `main` gets fixes. See [releases](https://github.com/Shadowprofessor/DDOS-Attack-Detection/releases/latest).

## How to report a vulnerability

**Please do not open a public issue with details.**

1. **Preferred:** use GitHub private vulnerability reporting on the
   [Security tab → "Report a vulnerability"](https://github.com/Shadowprofessor/DDOS-Attack-Detection/security/advisories/new),
   if the button is shown.
2. **Otherwise:** open an issue titled **"Security contact request"** with **no technical details**. The
   maintainer will reply with a private channel.

Please include:
- the affected file or endpoint;
- the version or commit;
- the steps to reproduce against a **local** instance;
- the impact.

**What to expect:**
- an acknowledgement within **72 hours**;
- a triage assessment with a severity (CVSS) within **7 days**;
- a fix in the next release, credited in the CHANGELOG unless you prefer to stay anonymous.

**Severity guidance:**
- Any path that bypasses the human approval gate is **critical**.
- Prompt injection that changes a proposed action is **high**.

Please do not include working exploits against third-party systems.

## In scope

- **Bypassing the approval gate:** any way a model, LLM output or API call enforces a block without
  `PendingActionManager.approve()` by an admin.
- Prompt injection through telemetry that changes the analyst's output beyond the code-enforced policy.
- Auth, session, CSRF or RBAC flaws in the API or the SOC web app (`/app`).
- Lab safety escapes: traffic leaving the Mininet scope, or the enforcer applying a rule it should refuse.
- Secrets exposure (for example, the alert webhook URL or API keys appearing in logs or responses).

## Out of scope

- Denial-of-service against your own running instance (it is a lab tool).
- The mocked Cloudflare connector.
- Findings that need an already-compromised host or admin key.
- Reports generated only by automated scanners, without a working reproduction.

## Rules

Test only against your own local instance and lab. Never test against systems you do not own. Do not
generate attack traffic outside an isolated lab: see the lab safety rules in
[docs/purple_team/README.md](docs/purple_team/README.md).
