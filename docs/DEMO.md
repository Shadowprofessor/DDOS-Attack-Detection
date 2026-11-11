# 60-second demo

Everything here runs locally with **no live traffic and no LLM key**: the analyst uses its
deterministic rule fallback, and replays use stored scenarios.

```bash
# 0. once
pip install -r requirements.txt
(cd dashboard && npm ci && npm run build)

# 1. detection core in the terminal (~10 s): benign/attack flows, low-and-slow, zero-day flag
python -m src.demo

# 2. start the platform with throwaway keys
export DDOS_API_KEYS=demo-analyst-key-01 DDOS_ADMIN_KEYS=demo-admin-key-0001
python -m uvicorn src.api.app:app --port 8000

# 3. (second terminal) score one attack-looking flow -> a PENDING mitigation proposal, nothing executed
curl -s -X POST localhost:8000/score/flow -H "X-API-Key: $DDOS_API_KEYS" -H "Content-Type: application/json" \
     -d '{"features":{"src_ip":"10.0.0.9","dst_ip":"10.0.0.4","Protocol":6,"SYN Flag Count":100}}'
```

Then in the browser, at <http://localhost:8000/app>:

| Time | Do | What it shows |
|---|---|---|
| 0–10 s | Sign in with `demo-admin-key-0001` | Session cookie; the key never stays in the browser |
| 10–20 s | **Replay** → `syn_flood` → *Run replay* | L1 alerts → L2 verdict → rule L3 produce an `[REPLAY]` incident |
| 20–30 s | Open that incident → *Run analysis* | AI recommendation panel, labelled as a recommendation, with provenance (rules here) |
| 30–45 s | **Approvals** → the proposal from step 3 → *Approve…* → confirm | The only way a block ever happens: a human admin, through a confirmation dialog |
| 45–60 s | Incident → *Export PDF*; then **Overview** | Hash-chained timeline (verified) in the PDF; KPIs and CERT-In countdowns |

Replay incidents send any playbook "Request action" to an isolated dry-run queue, so they never
appear on the Approvals page. The scored flow in step 3 is what creates a real proposal.
