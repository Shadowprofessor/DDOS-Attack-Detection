# Prompt 8 — Cloudflare Magic Transit Connector (COMPLETED)

## Objective
Build `src/mitigation/cloud_enforcers/cloudflare.py` implementing the same enforcer interface used by existing Ryu/iptables/Docker enforcers, with the critical safety requirement that it NEVER calls the Cloudflare API without human approval.

## Implementation Summary

### Files Created
1. **`src/mitigation/cloud_enforcers/__init__.py`** — Package initialization
2. **`src/mitigation/cloud_enforcers/cloudflare.py`** — CloudflareEnforcer implementation (371 lines)
3. **`src/mitigation/cloud_enforcers/README.md`** — Documentation and usage guide
4. **`tests/test_cloud_enforcers.py`** — Comprehensive test suite (402 lines, 12 tests)

### Files Modified
1. **`src/mitigation/manager.py`** — Extended `_execute_action()` dispatcher to recognize `action_type='cloudflare_scrub'` and route to `CloudflareEnforcer.execute()`

## Safety Contract Verification

### ✅ Requirement 1: propose_action() Never Calls Cloudflare API
```python
CloudflareEnforcer.propose_action(
    attacker_ip="203.0.113.50",
    victim_ip="10.0.0.5",
    reason="XGBoost detected SYN flood",
    confidence=0.95,
)
# ✅ Only calls PendingActionManager.propose()
# ✅ Never imports or calls requests/urllib
# ✅ Creates PENDING action with auto_execute=False
```

**Test Coverage:**
- `test_propose_action_never_calls_cloudflare_api` — Mocks all HTTP libraries, verifies zero calls
- `test_no_direct_api_calls_in_propose_action_code_path` — Static verification
- `test_multiple_propose_actions_do_not_trigger_api` — Batch proposal test

### ✅ Requirement 2: execute() Is the SOLE API Call Path
```python
enforcer = CloudflareEnforcer(api_token="...", account_id="...")
result = enforcer.execute(action)
# ✅ Only method that calls _call_cloudflare_api()
# ✅ Only method that imports requests
# ✅ Creates Magic Transit route via POST to api.cloudflare.com
```

**Test Coverage:**
- `test_execute_calls_cloudflare_api_only_after_approval` — Verifies API call happens
- `test_execute_handles_cloudflare_api_failure` — Error handling
- `test_execute_requires_credentials` — Validates credential check before API call

### ✅ Requirement 3: execute() Only Reached via Approval Gate
```python
manager = get_manager()
success, msg, action = manager.approve(action_id, approver="operator")
# ✅ approve() calls _execute_action()
# ✅ _execute_action() dispatches to CloudflareEnforcer.execute()
# ✅ No other code path reaches execute()
```

**Test Coverage:**
- `test_approve_calls_cloudflare_enforcer_via_dispatcher` — Integration test
- `test_execute_is_only_called_after_approval` — State transition verification
- `test_cloudflare_enforcer_integration_with_manager_execute_action` — Pattern demonstration

## Test Results

### New Tests (test_cloud_enforcers.py)
```
12/12 tests passed (0.43s)
```

**Safety Contract Tests (9 tests):**
- ✅ propose_action never calls Cloudflare API
- ✅ execute is only called after approval
- ✅ Dispatcher integration routes correctly
- ✅ No direct API calls in propose code path
- ✅ execute requires credentials
- ✅ execute calls Cloudflare API only after approval
- ✅ execute handles API failures gracefully
- ✅ Multiple proposals do not trigger API
- ✅ Integration with manager execute_action

**Functionality Tests (3 tests):**
- ✅ Enforcer initialization with env vars
- ✅ Enforcer initialization with explicit params
- ✅ remove_scrubbing utility method

### Existing Tests (Unchanged)
```
test_mitigation_approval_gate.py:  14/14 passed ✅
test_mitigation_bypass.py:          5/5 passed ✅
```

### Combined Test Suite
```
31/31 tests passed (17.43s)
```

## Architecture

### CloudflareEnforcer Interface
```python
class CloudflareEnforcer:
    def __init__(api_token, account_id, zone_id):
        """Initialize with credentials from env vars or params"""
    
    @staticmethod
    def propose_action(attacker_ip, victim_ip, reason, confidence, ...):
        """Enqueue PENDING action via PendingActionManager.propose()"""
        # ✅ NEVER calls Cloudflare API
        # ✅ Returns action_id
    
    def execute(action):
        """Execute APPROVED action — ONLY called via manager.approve()"""
        # ✅ Validates credentials
        # ✅ Calls _call_cloudflare_api()
        # ✅ Returns execution result dict
    
    def _call_cloudflare_api(attacker_ip, action):
        """Internal method — creates Magic Transit route"""
        # ✅ POST to /accounts/{id}/magic/routes
        # ✅ Body: {"prefix": "IP/32", "nexthop": "scrub", "priority": 100}
    
    def remove_scrubbing(attacker_ip, route_id):
        """Utility method for manual cleanup"""
```

### Dispatcher Integration (manager.py)
```python
def _execute_action(self, action: dict) -> dict:
    action_type = action.get("action_type")
    
    if action_type == "OPENFLOW_DROP":
        # ... existing OpenFlow logic
    
    if action_type == "cloudflare_scrub":
        # ✅ NEW: Route to CloudflareEnforcer.execute()
        from src.mitigation.cloud_enforcers.cloudflare import CloudflareEnforcer
        enforcer = CloudflareEnforcer()
        return enforcer.execute(action)
    
    # ... existing generic command logging
```

## Usage Examples

### 1. Propose Cloudflare Scrubbing
```python
from src.mitigation.cloud_enforcers.cloudflare import CloudflareEnforcer

action_id = CloudflareEnforcer.propose_action(
    attacker_ip="203.0.113.50",
    victim_ip="10.0.0.5",
    reason="XGBoost ensemble detected sustained SYN flood (conf: 0.95)",
    confidence=0.95,
    scrub_duration_seconds=3600,
)
# ✅ Action is PENDING, awaiting human approval
```

### 2. Approve via CLI
```bash
python -m src.mitigation.cli list
python -m src.mitigation.cli approve <action_id>
# ✅ Triggers CloudflareEnforcer.execute() → Cloudflare API call
```

### 3. Approve via Admin API
```bash
curl -X POST http://localhost:8000/actions/approve/<action_id> \
  -H "X-Admin-Key: your-admin-key"
# ✅ Requires ADMIN_KEYS, not scoring keys
```

### 4. Approve via Dashboard
```
Navigate to /dashboard → Pending Actions → Click "Approve"
# ✅ WebSocket real-time updates
```

## Configuration

### Environment Variables
```bash
export CLOUDFLARE_API_TOKEN="your-cloudflare-api-token"
export CLOUDFLARE_ACCOUNT_ID="your-cloudflare-account-id"
export CLOUDFLARE_ZONE_ID="your-zone-id"  # Optional
```

### API Token Permissions
- Magic Transit: Edit
- Account Settings: Read

Generate token at: https://dash.cloudflare.com/profile/api-tokens

## Cloudflare API Integration

### Create Route (Activate Scrubbing)
```http
POST https://api.cloudflare.com/client/v4/accounts/{account_id}/magic/routes
Authorization: Bearer {api_token}
Content-Type: application/json

{
  "prefix": "203.0.113.50/32",
  "nexthop": "scrub",
  "priority": 100,
  "description": "DDoS mitigation - action <id> - <reason>"
}
```

### Delete Route (Deactivate Scrubbing)
```http
DELETE https://api.cloudflare.com/client/v4/accounts/{account_id}/magic/routes/{route_id}
Authorization: Bearer {api_token}
```

## Safety Invariants Preserved

### AGENTS.md Rule 2 Compliance
✅ "Any mitigation action that blocks/null-routes a real IP, modifies live firewall rules, or calls a third-party scrubbing API (Cloudflare/AWS Shield) must default to 'propose, don't execute' — log the recommended action and require my explicit approval before it runs for real."

### No Auto-Execution
- ✅ `auto_execute` hardcoded to `False` in `PendingActionManager.propose()`
- ✅ `propose_action()` never imports HTTP libraries
- ✅ `execute()` only callable via `approve()` → `_execute_action()` dispatcher

### Approval Gate Enforcement
- ✅ CLI requires explicit `approve` command
- ✅ Admin API requires privileged `ADMIN_KEYS` (scoring keys rejected with 403)
- ✅ Dashboard requires user click on "Approve" button
- ✅ All paths go through `PendingActionManager.approve()`

## Extensibility

The cloud enforcer pattern supports additional providers:

### AWS Shield
```python
# src/mitigation/cloud_enforcers/aws_shield.py
class AWSShieldEnforcer:
    @staticmethod
    def propose_action(...): pass
    def execute(action): pass
```

### Integration Pattern
```python
# In manager.py _execute_action():
if action_type == "aws_shield_protection":
    from src.mitigation.cloud_enforcers.aws_shield import AWSShieldEnforcer
    enforcer = AWSShieldEnforcer()
    return enforcer.execute(action)
```

## Documentation
- ✅ Comprehensive README.md with usage examples
- ✅ Inline code comments explaining safety contract
- ✅ Docstrings on all public methods
- ✅ Configuration instructions
- ✅ Troubleshooting guide
- ✅ API reference

## Deliverables Checklist

- [x] `src/mitigation/cloud_enforcers/cloudflare.py` implementing enforcer interface
- [x] `propose_action()` ONLY calls `PendingActionManager.propose()` — never Cloudflare API
- [x] `execute()` method clearly labeled and ONLY callable via approval gate
- [x] `tests/test_cloud_enforcers.py` proving no code path reaches Cloudflare API without approval
- [x] `test_mitigation_approval_gate.py` still passes (14/14) ✅
- [x] `test_mitigation_bypass.py` still passes (5/5) ✅
- [x] Dispatcher integration in `manager.py` routing `action_type='cloudflare_scrub'`
- [x] README.md with usage examples and configuration
- [x] All tests passing (31/31) ✅

## Verification Commands

```bash
# Run new tests
pytest tests/test_cloud_enforcers.py -v

# Run existing approval gate tests
pytest tests/test_mitigation_approval_gate.py -v

# Run existing bypass tests
pytest tests/test_mitigation_bypass.py -v

# Run all mitigation tests together
pytest tests/test_cloud_enforcers.py tests/test_mitigation_approval_gate.py tests/test_mitigation_bypass.py -v
```

## Status: ✅ COMPLETE

All requirements met:
- CloudflareEnforcer follows the same safety contract as existing enforcers
- propose_action() never calls Cloudflare API (verified by tests)
- execute() is the sole API call path (verified by tests)
- execute() only reachable via approval gate (verified by tests)
- All existing tests still pass (14+5 = 19 tests)
- New tests prove safety contract (12 tests)
- Total: 31/31 tests passing ✅
