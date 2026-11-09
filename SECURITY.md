# Security Policy

## Scope
This is a **defensive** DDoS detection & response platform. It contains no code intended to
launch attacks against third parties. Attack-traffic generation exists only for isolated,
owned lab environments (Mininet/containers).

## Supported versions
The latest `v4.x` release line receives security fixes. Older tags are not maintained.

| Version | Supported |
|---|---|
| 4.0.x (latest) | ✅ |
| < 4.0 | ❌ |

## Reporting a vulnerability
Please report security issues **privately** — do not open a public issue for an unfixed
vulnerability.

- Preferred: open a **GitHub private vulnerability report** (repo → Security → *Report a
  vulnerability*).
- Alternatively, email the maintainer (see `.well-known/security.txt`).

Include: affected version/commit, a description, reproduction steps or PoC, and impact.
Please do not include working exploits against third-party systems.

## What to expect
- Acknowledgement within **72 hours**.
- A triage assessment and severity (CVSS) within **7 days**.
- Fixes released on the `v4.x` line with credit in the `CHANGELOG`, unless you prefer anonymity.

## Handling guidance
- Never commit secrets; keys load from env / a gitignored `.env` only.
- All mitigation actions are human-approved (`PendingActionManager.approve()`); report any path
  that could bypass that gate as **critical**.
- The LLM analyst is read-only and receives aggregated telemetry only; report prompt-injection
  that changes a proposed action as **high**.
