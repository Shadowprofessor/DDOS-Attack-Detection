# Control mapping (v5.0.0)

How the platform's controls line up with common frameworks, and what evidences each one. This is
an **engineering self-assessment**, not an audit or a certification. "Partial" means the platform
covers the technical part and an organisation still owns the process part (people, policy,
records).

Frameworks:
- NIST CSF 2.0 (<https://www.nist.gov/cyberframework>), including the SP 800-61r3 incident-response
  profile (<https://csrc.nist.gov/pubs/sp/800/61/r3/final>);
- ISO/IEC 27001:2022 Annex A (<https://www.iso.org/standard/27001>);
- CIS Critical Security Controls v8 (<https://www.cisecurity.org/controls/v8>);
- CERT-In Directions 20(3)/2022 (<https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf>);
- MITRE D3FEND (<https://d3fend.mitre.org/>).

| Platform control | NIST CSF 2.0 | ISO 27001:2022 Annex A | CIS v8 | D3FEND | Coverage | Evidence |
|---|---|---|---|---|---|---|
| L1 network monitoring: sanity, signature, rate thresholds, low-and-slow | DE.CM-01 (networks monitored) | 8.16 Monitoring activities, 8.20 Networks security | 13.3 Network intrusion detection, 13.1 Centralise security event alerting | [D3-NTA](https://d3fend.mitre.org/technique/d3f:NetworkTrafficAnalysis/), [D3-ISVA](https://d3fend.mitre.org/technique/d3f:InboundSessionVolumeAnalysis/) | Technical: yes. Lab shows false positives (flash crowd) | `tests/test_threshold_detector.py`, `docs/purple_team/README.md` |
| Signature filter | DE.CM-01 | 8.16 | 13.3 | [D3-NTSA](https://d3fend.mitre.org/technique/d3f:NetworkTrafficSignatureAnalysis/) | Yes | `tests/test_signature_filter.py` |
| L2 ML ensemble + OOD detector | DE.AE-02 (adverse events analysed) | 8.16 | 13.3 | D3-NTA | **Partial**: same-dataset only; missed lab SYN flood; inconclusive cross-dataset | `docs/eval/cross_dataset.md`, `docs/purple_team/README.md` |
| L3 analyst: one call per incident, recommendation only, injection defences | DE.AE-02, RS.AN (incident analysis) | 5.25 Assessment and decision on events | 17.9 Incident thresholds | — | Yes (advisory) | `tests/test_threat_analyst.py`, `tests/test_injection_policy.py` |
| Incident lifecycle (NIST 800-61r3 states), playbooks | RS.MA-01 (IR plan executed), RS.MI-01 / RS.MI-02 (contain / eradicate), RC.RP-01 (recovery) | 5.24 IR planning, 5.26 Response to incidents | 17.4 Incident response process | — | Technical: yes. Plan ownership is organisational | `tests/test_ir.py`, `docs/IR.md` |
| Hash-chained incident timeline + MD/PDF export | RS.AN (records), ID.IM (improvement) | 5.28 Collection of evidence, 5.27 Learning from incidents | 8.2 Collect audit logs | — | Tamper-evident (not tamper-proof) | `tests/test_ir.py::TestHashChain` |
| CERT-In 6 h timer + report draft (never auto-submitted) | RS.CO-02 (stakeholders notified) | 5.5 Contact with authorities, 5.26 | 17.6 Communicating during IR | — | Draft + timer; submission is a human step | `tests/test_ir.py::TestCertIn` |
| Human-approved mitigation (`PendingActionManager.approve()` only) + auto-rollback | RS.MI-01 | 8.20, 8.32 Change management | 13.10 Application-layer filtering | [D3-ITF](https://d3fend.mitre.org/technique/d3f:InboundTrafficFiltering/) | Yes | `tests/test_mitigation_bypass.py` (AST), `tests/test_ir.py::TestRollback` |
| RBAC, sessions, CSRF, CSP | PR.AA (identity and access) | 5.15 Access control, 8.2 Privileged access rights, 8.5 Secure authentication | 6.8 Role-based access control | — | Yes (shared keys, no per-user identity / MFA) | `tests/test_ir_api.py::TestRBACMatrix`, `tests/test_soc_session.py` |
| Logging: JSON logs, `log_safe`, Prometheus metrics | DE.CM (monitoring) | 8.15 Logging | 8.2, 8.5 Collect detailed audit logs | — | Yes; `/metrics` unauthenticated (accepted) | `tests/test_observability.py`, `tests/test_codeql_hardening.py` |
| Secure SDLC: CodeQL, Bandit, gitleaks, pip/npm audit, pinned deps, SBOM, Dependabot | PR.PS-06 (secure software development), GV.SC (supply chain) | 8.25 Secure development life cycle, 8.28 Secure coding, 8.8 Technical vulnerabilities | 16.12 Code-level security checks, 7.1 Vulnerability management process | — | Yes | `.github/workflows/`, release SBOMs |
| Security testing: STRIDE, bug hunt, purple team, hunts | ID.RA (risk assessment), ID.IM | 8.29 Security testing in development and acceptance | 18 Penetration testing (partial: internal) | — | Partial (internal, not independent) | `docs/security/`, `docs/purple_team/`, `docs/hunts/` |
| Lab containment (scope, caps, kill switch, nftables egress drop) | PR.IR (infrastructure resilience) | 8.22 Segregation of networks | 12 Network infrastructure management | [D3-OTF](https://d3fend.mitre.org/technique/d3f:OutboundTrafficFiltering/), [D3-NI](https://d3fend.mitre.org/technique/d3f:NetworkIsolation/) | Yes (lab only) | `tests/test_lab_safety.py`, measured containment |

**Not covered (organisational):** governance (GV.OC, GV.RR, GV.PO), awareness training (PR.AT),
supplier contracts, business continuity, and the CERT-In 180-day log-retention requirement (not
configured by default).
