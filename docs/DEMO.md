# 5-minute demo (live attack → alert → AI → human-approved containment)

For a teacher, recruiter or reviewer. You do the clicks; the platform does the detecting.
Set-up takes about 2 minutes before they arrive: RUNBOOK → **H. Live demo**.

**Before they sit down**
- Windows 1–3 are running (server, bridge, `demo_assist.py`).
- The browser is signed in with the **admin** key `demo-admin-key-0001`, on **Live attack**.
- Settings → Alerts → *Send test alert* beeped once, and the sound is on.
- The WSL terminal has this command typed but **not yet run**:
  `sudo mn -c; sudo CONTAIN=1 bash lab/live_demo.sh live9`.
- These are open in tabs: `docs/purple_team/dev_vs_heldout.md` and `REPORT.md`.

## The script

| Time | You do | They see | You say |
|---|---|---|---|
| 0:00 | Point at the screen | Live attack page, flat chart, "No active L1 alert" | "This is a SOC website watching a lab network: a victim server, an attacker, a client, all inside Mininet on this laptop. Nothing leaves the laptop." |
| 0:20 | Press Enter in WSL | "containment proof … contained" in the terminal | "First it proves the lab can't reach the internet: 3 of 3 probe packets are dropped at the boundary." |
| 0:50 | Wait | Banner **Attack in progress**, chart jumps to ~3k pkt/s; an **alert toast** with 2 beeps | "A 50-source SYN flood just started. It was on this screen in 3–5 seconds. The toast says *why*: the packet rate, the SYN share, and that the CERT-In 6-hour reporting clock has started." |
| 1:20 | Click **Open INC-…** in the toast | Incident page: **Why it was flagged**, the AI verdict, then the **AI containment plan** | "The rule layer detected it. The AI, NVIDIA Nemotron, explains what it is and proposes a plan. Each step shows how much of the attack it would stop. That number is measured from the switch, not guessed by the AI." |
| 2:00 | Click **Approvals** | One PENDING `LAB_OVS_PORT_DROP attacker`, 5 min TTL, reversible | "The AI cannot block anything. Its step is only a proposal. A human admin has to approve it. That's me." |
| 2:20 | *Approve…* → *Approve and enforce* | "Approve: … done", then an auto-rollback countdown | "Approved. The lab enforcer installs a switch rule that removes itself after 5 minutes." |
| 2:30 | Click **Live attack** | Lab containment: `applied`; the chart drops to **0** | "Applied in about half a second. The victim's traffic fell to zero 2.6 s after I clicked: that's our measured time to contain." |
| 3:00 | Back to the incident → **Export PDF** | PDF with the timeline and hash chain | "Every step is in a tamper-evident timeline: who approved, when, and what the AI said. That's what goes to the incident report." |
| 3:30 | Show `dev_vs_heldout.md` | Coverage matrix, DEV vs HELD-OUT | "We tuned the rules on two lab runs, then froze them and ran a fresh one we'd never looked at. Held-out: 10 of 10 attacks detected and named, 0 false positives on normal traffic and a flash crowd." |
| 4:15 | Show `REPORT.md` §5.6 and §7 | Triage table and limitations | "We report the misses too. The AI named the live UDP flood a *SYN* flood in 3 of 4 runs. The rules were right, and the rules' verdict is shown next to it. The ML is strong in the lab but unproven on real internet traffic." |
| 4:45 | — | — | "So: detection in seconds, an AI that explains and recommends, and a human who decides. Containment was measured at 2.6 seconds." |

The UDP flood starts about 2:15 after the SYN flood. If your rule is still active (5 min), it blocks
that flood too, because it comes through the same attacker port. You can point this out. To see a
second alert, approve with a shorter TTL or wait for the rule to expire.

## If something breaks

| Symptom | Cause | Fix (≤ 30 s) |
|---|---|---|
| `uvicorn : The term 'uvicorn' is not recognized` | the `.exe` is not on PATH | `python -m uvicorn src.api.app:app --host 127.0.0.1 --port 8000` |
| `[Errno 10048] error while attempting to bind` (port 8000 busy) | an old server is still running | Ctrl+C it, or `Get-NetTCPConnection -LocalPort 8000 \| Select OwningProcess` then `Stop-Process -Id <pid>` |
| Bridge prints `waiting for the platform` | the server isn't up yet | Start Window 1; the bridge connects by itself |
| Attack running but **no banner / no incident** | bridge started on a different run id, or not started | The bridge folder must match the WSL run id (`data/lab_runs/live9` ↔ `live_demo.sh live9`). Restart the bridge with the right id; it picks up new pcaps |
| Window 3 says "proposes no lab step" | the AI plan had no lab step | Open the incident → *Ask the agent* again, or *Propose…* on a plan row yourself |
| AI verdict says **source: rules** / "degraded" | no `NVIDIA_API_KEY`, or the NVIDIA API timed out | Say so; it's by design. The rule analyst answers instead, and nothing depends on the AI |
| Approved, but Lab containment never shows `applied` | the WSL script wasn't started with `CONTAIN=1`, or the approval was for an old item | Approve the id Window 3 printed. The enforcer refuses approvals from earlier runs |
| `lab/KILL exists` in WSL | the last run was stopped with the kill switch | `rm lab/KILL` |
| No sound | the browser blocks audio until you click on the page | Click anywhere once, or Settings → *Send test alert* |
| Anything else | — | Fall back to the offline demo below. It needs no WSL and no key |

## Offline fallback (60 s, no WSL, no LLM key)

```bash
python -m src.demo                                 # detection core in the terminal (~10 s)
# Window 1 as above (no NVIDIA key needed), then in the browser at http://localhost:8000/app:
```

| Do | What it shows |
|---|---|
| **Replay** → `syn_flood` → *Run replay* | L1 alerts → L2 verdict → rule L3 produce an `[REPLAY]` incident |
| Open it → *Run analysis* | AI recommendation panel with provenance (rules here) |
| **Approvals** | Any real proposal stays PENDING until an admin approves |
| Incident → *Export PDF*; then **Overview** | Hash-chained timeline in the PDF; KPIs and CERT-In countdowns |

Replay incidents send any playbook "Request action" to an isolated dry-run queue, so they never
appear on Approvals. Label replay numbers as *replay*, not live.
