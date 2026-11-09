# Cloud Enforcers — Third-Party DDoS Mitigation Integration

This module provides integrations with cloud-based DDoS mitigation services
(Cloudflare Magic Transit, AWS Shield, etc.) that follow the same safety
contract as local enforcers.

## Safety Contract

All cloud enforcers follow the human-in-the-loop approval gate:

1. **propose_action()** — Enqueues a PENDING action with `auto_execute=False`
2. **execute()** — ONLY called by `PendingActionManager._execute_action()` after human approval
3. **No API calls** are made until explicit approval via CLI, dashboard, or admin API

This ensures no cloud mitigation action is triggered directly from detection/scoring code.

---

## Cloudflare Magic Transit Enforcer

### Overview

`CloudflareEnforcer` integrates Cloudflare Magic Transit IP scrubbing for DDoS mitigation.
When approved, it creates a static route that directs traffic from an attacker IP through
Cloudflare's scrubbing infrastructure.

### Configuration

Set the following environment variables:

```bash
export CLOUDFLARE_API_TOKEN="your-cloudflare-api-token"
export CLOUDFLARE_ACCOUNT_ID="your-cloudflare-account-id"
export CLOUDFLARE_ZONE_ID="your-zone-id"  # Optional
```

**API Token Permissions Required:**
- Magic Transit: Edit
- Account Settings: Read

Generate a token at: https://dash.cloudflare.com/profile/api-tokens

### Usage

#### 1. Propose a Cloudflare Scrubbing Action

```python
from src.mitigation.cloud_enforcers.cloudflare import CloudflareEnforcer

# Propose scrubbing for an attacker IP
action_id = CloudflareEnforcer.propose_action(
    attacker_ip="203.0.113.50",
    victim_ip="10.0.0.5",
    reason="XGBoost ensemble detected sustained SYN flood (conf: 0.95)",
    confidence=0.95,
    scrub_duration_seconds=3600,  # 1 hour (note: Cloudflare routes are persistent until deleted)
)

print(f"Action proposed: {action_id} — awaiting human approval")
```

**SAFETY:** `propose_action()` does NOT call the Cloudflare API. It only enqueues
a PENDING action in the unified mitigation manager.

#### 2. Approve the Action (Human-in-the-Loop)

**Option A: CLI**

```bash
python -m src.mitigation.cli list
python -m src.mitigation.cli approve <action_id>
```

**Option B: Dashboard**

Navigate to `/dashboard` and click "Approve" on the pending action.

**Option C: Admin API**

```bash
curl -X POST http://localhost:8000/actions/approve/<action_id> \
  -H "X-Admin-Key: your-admin-key"
```

When approved, `PendingActionManager._execute_action()` dispatches to
`CloudflareEnforcer.execute()`, which calls the Cloudflare Magic Transit API.

#### 3. Remove Scrubbing (Manual Cleanup)

```python
enforcer = CloudflareEnforcer()
success, msg = enforcer.remove_scrubbing("203.0.113.50")
print(msg)
```

### Integration with Detection Pipeline

Example: Integrate with the FastAPI scoring service or Nemotron agent:

```python
from src.mitigation.cloud_enforcers.cloudflare import CloudflareEnforcer
from src.agent.nemotron_agent import NemotronAgent

# In scoring_service.py or nemotron_agent.py:
if attack_detected and confidence >= 0.90:
    # Propose local SDN mitigation
    local_action_id = manager.propose(
        action_type="OPENFLOW_DROP",
        attacker_ip=attacker_ip,
        victim_ip=victim_ip,
        reason="Local SDN drop",
        confidence=confidence,
    )
    
    # ALSO propose Cloudflare scrubbing for upstream protection
    cloudflare_action_id = CloudflareEnforcer.propose_action(
        attacker_ip=attacker_ip,
        victim_ip=victim_ip,
        reason=f"Upstream scrubbing for attack detected by {source}",
        confidence=confidence,
        scrub_duration_seconds=3600,
    )
    
    # Both actions require separate human approval before execution
```

### Cloudflare API Reference

The enforcer uses the following Cloudflare API endpoints:

- **Create Route (Activate Scrubbing):**
  ```
  POST https://api.cloudflare.com/client/v4/accounts/{account_id}/magic/routes
  Body: {"prefix": "203.0.113.50/32", "nexthop": "scrub", "priority": 100}
  ```

- **List Routes:**
  ```
  GET https://api.cloudflare.com/client/v4/accounts/{account_id}/magic/routes
  ```

- **Delete Route (Deactivate Scrubbing):**
  ```
  DELETE https://api.cloudflare.com/client/v4/accounts/{account_id}/magic/routes/{route_id}
  ```

See: https://developers.cloudflare.com/api/operations/magic-static-routes-create-route

---

## Testing

Run the cloud enforcer test suite:

```bash
pytest tests/test_cloud_enforcers.py -v
```

**Key Test Coverage:**
- `propose_action()` never calls Cloudflare API (safety contract)
- `execute()` is only called after approval
- No code path reaches Cloudflare API without approved action
- Dispatcher integration routes `action_type='cloudflare_scrub'` correctly
- Credential validation and error handling

---

## Extending to Other Cloud Providers

To add AWS Shield, Akamai, or other cloud mitigation services:

1. Create `src/mitigation/cloud_enforcers/aws_shield.py` (or similar)
2. Implement the same interface:
   - `propose_action(attacker_ip, victim_ip, reason, ...) -> action_id`
   - `execute(action) -> result_dict`
3. Add dispatcher case to `manager.py`:
   ```python
   if action_type == "aws_shield_protection":
       from src.mitigation.cloud_enforcers.aws_shield import AWSShieldEnforcer
       enforcer = AWSShieldEnforcer()
       return enforcer.execute(action)
   ```
4. Add tests to `tests/test_cloud_enforcers.py`

---

## Security Notes

- **API Tokens:** Store in environment variables or secure vault, never in source code
- **Approval Gate:** All cloud enforcers MUST respect the approval gate (see AGENTS.md Rule 2)
- **Blast Radius:** Cloud scrubbing affects all traffic to the target IP, including legitimate users
  routed through that IP. Use with caution and coordinate with network operations.
- **Cost:** Cloudflare Magic Transit and similar services may incur usage-based costs. Review
  pricing before enabling automated mitigation at scale.

---

## Troubleshooting

**Error: "CLOUDFLARE_API_TOKEN not set"**
- Set the `CLOUDFLARE_API_TOKEN` environment variable before starting the service

**Error: "CLOUDFLARE_ACCOUNT_ID not set"**
- Set the `CLOUDFLARE_ACCOUNT_ID` environment variable

**Error: HTTP 403 Forbidden**
- Verify API token has "Magic Transit: Edit" permissions
- Check token is not expired

**Error: HTTP 404 Not Found**
- Verify `CLOUDFLARE_ACCOUNT_ID` is correct
- Ensure Magic Transit is enabled for your Cloudflare account

**Action approved but scrubbing not active:**
- Check execution result in `manager.get_action(action_id)["execution_result"]`
- Review Cloudflare dashboard: https://dash.cloudflare.com/ → Magic Transit → Routes
- Verify route was created with `enforcer._call_cloudflare_api()` logs

---

## License & Attribution

Part of the DDoS Attack Detection and Mitigation System.
See repository root LICENSE file.
