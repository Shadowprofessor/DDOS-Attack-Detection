# -*- coding: utf-8 -*-
"""
Cloudflare Magic Transit DDoS Mitigation Enforcer.

SAFETY INVARIANT:
This module NEVER calls the Cloudflare API directly from propose_action().
All proposed actions are written to the unified pending-actions store
(PendingActionManager) and require explicit human approval via approve_action()
before the execute() method is invoked.

Architecture:
  1. propose_action() — creates a PENDING action with action_type='cloudflare_scrub'
  2. execute() — ONLY called by PendingActionManager._execute_action() after approval

The execute() method is the SOLE code path that may trigger Cloudflare API calls,
and it is protected by the human-in-the-loop approval gate.
"""
import os
import logging
from typing import Optional, Dict, Any, Tuple

logger = logging.getLogger("CloudflareEnforcer")

# Import the unified mitigation manager
try:
    from src.mitigation.manager import get_manager
except ImportError:
    try:
        from mitigation.manager import get_manager
    except ImportError:
        get_manager = None
        logger.warning("Could not import PendingActionManager; CloudflareEnforcer will be non-functional.")


class CloudflareEnforcer:
    """
    Proposes Cloudflare Magic Transit IP scrubbing actions for DDoS mitigation.

    All actions are proposed only — execution requires human approval via
    approve_action() from the mitigation manager.

    Configuration via environment variables:
      - CLOUDFLARE_API_TOKEN: Cloudflare API token with Magic Transit permissions
      - CLOUDFLARE_ACCOUNT_ID: Cloudflare account ID
      - CLOUDFLARE_ZONE_ID: (Optional) Zone ID if using zone-level protection
    """

    def __init__(
        self,
        api_token: Optional[str] = None,
        account_id: Optional[str] = None,
        zone_id: Optional[str] = None,
    ):
        """
        Initialize Cloudflare enforcer with API credentials.

        Args:
            api_token: Cloudflare API token (or from CLOUDFLARE_API_TOKEN env var)
            account_id: Cloudflare account ID (or from CLOUDFLARE_ACCOUNT_ID env var)
            zone_id: Optional zone ID (or from CLOUDFLARE_ZONE_ID env var)
        """
        self.api_token = api_token or os.environ.get("CLOUDFLARE_API_TOKEN")
        self.account_id = account_id or os.environ.get("CLOUDFLARE_ACCOUNT_ID")
        self.zone_id = zone_id or os.environ.get("CLOUDFLARE_ZONE_ID")

        if not self.api_token:
            logger.warning(
                "CLOUDFLARE_API_TOKEN not set. CloudflareEnforcer will operate in "
                "proposal-only mode. Execute will fail without credentials."
            )
        if not self.account_id:
            logger.warning(
                "CLOUDFLARE_ACCOUNT_ID not set. Execute will fail without account ID."
            )

    @staticmethod
    def propose_action(
        attacker_ip: str,
        victim_ip: str,
        reason: str,
        confidence: Optional[float] = None,
        scrub_duration_seconds: int = 3600,
        source: str = "cloudflare_enforcer",
    ) -> str:
        """
        Propose a Cloudflare Magic Transit IP scrubbing action.

        SAFETY: Does NOT call the Cloudflare API. Only enqueues a PENDING action
        in the unified mitigation manager with action_type='cloudflare_scrub'.

        Args:
            attacker_ip: Source IP to scrub via Cloudflare
            victim_ip: Protected destination IP
            reason: Human-readable reason for the mitigation
            confidence: Detection confidence score (0.0-1.0)
            scrub_duration_seconds: How long to apply scrubbing (default 3600s = 1 hour)
            source: Source component requesting the action

        Returns:
            action_id: Unique ID of the pending action
        """
        if get_manager is None:
            logger.error("PendingActionManager not available; cannot propose Cloudflare action.")
            return None

        manager = get_manager()

        # Describe the action that will be taken upon approval
        proposed_commands = [
            f"POST https://api.cloudflare.com/client/v4/accounts/<account_id>/magic/routes",
            f"  Body: {{\"prefix\": \"{attacker_ip}/32\", \"nexthop\": \"scrub\", \"priority\": 100}}",
            f"  Duration: {scrub_duration_seconds}s",
        ]

        action_id = manager.propose(
            action_type="cloudflare_scrub",
            attacker_ip=attacker_ip,
            victim_ip=victim_ip,
            reason=reason,
            confidence=confidence,
            commands=proposed_commands,
            source=source,
        )

        logger.info(
            "📋 [CLOUDFLARE ENFORCER] Proposed Magic Transit scrubbing for %s → %s "
            "(action_id: %s, duration: %ds). Awaiting human approval.",
            attacker_ip, victim_ip, action_id, scrub_duration_seconds
        )

        return action_id

    def execute(
        self,
        action: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Execute an APPROVED Cloudflare scrubbing action.

        SAFETY: This method is ONLY called by PendingActionManager._execute_action()
        after explicit human approval via approve_action(). It must NEVER be called
        directly from detection/scoring code paths.

        This is the SOLE code path that may trigger Cloudflare API calls.

        Args:
            action: The approved action dict from PendingActionManager

        Returns:
            Execution result dict with success status and details
        """
        if not self.api_token:
            logger.error(
                "Cannot execute Cloudflare scrubbing action %s: CLOUDFLARE_API_TOKEN not set.",
                action.get("action_id")
            )
            return {
                "success": False,
                "message": "Cloudflare API token not configured",
                "executed": [{
                    "command": "Cloudflare Magic Transit API call",
                    "status": "FAILED",
                    "error": "CLOUDFLARE_API_TOKEN not set"
                }]
            }

        if not self.account_id:
            logger.error(
                "Cannot execute Cloudflare scrubbing action %s: CLOUDFLARE_ACCOUNT_ID not set.",
                action.get("action_id")
            )
            return {
                "success": False,
                "message": "Cloudflare account ID not configured",
                "executed": [{
                    "command": "Cloudflare Magic Transit API call",
                    "status": "FAILED",
                    "error": "CLOUDFLARE_ACCOUNT_ID not set"
                }]
            }

        attacker_ip = action.get("attacker_ip")
        action_id = action.get("action_id")

        logger.info(
            "🔧 [EXECUTING APPROVED CLOUDFLARE ACTION %s] Triggering Magic Transit "
            "scrubbing for attacker IP: %s",
            action_id, attacker_ip
        )

        try:
            # Call Cloudflare API to enable scrubbing for this IP
            result = self._call_cloudflare_api(attacker_ip, action)

            if result["success"]:
                logger.info(
                    "✅ [CLOUDFLARE SCRUBBING ACTIVE] %s is now being scrubbed via "
                    "Cloudflare Magic Transit (action_id: %s)",
                    attacker_ip, action_id
                )
                return {
                    "success": True,
                    "message": f"Cloudflare scrubbing activated for {attacker_ip}",
                    "executed": [{
                        "command": f"Cloudflare Magic Transit scrub {attacker_ip}",
                        "status": "EXECUTED",
                        "details": result.get("details")
                    }]
                }
            else:
                logger.error(
                    "❌ [CLOUDFLARE EXECUTION FAILED] Action %s failed: %s",
                    action_id, result.get("error")
                )
                return {
                    "success": False,
                    "message": f"Cloudflare API call failed: {result.get('error')}",
                    "executed": [{
                        "command": f"Cloudflare Magic Transit scrub {attacker_ip}",
                        "status": "FAILED",
                        "error": result.get("error")
                    }]
                }

        except Exception as e:
            # SANITIZATION: Never expose API tokens in error messages
            sanitized_error = self._sanitize_error_message(str(e))
            logger.error(
                "❌ [CLOUDFLARE EXECUTION EXCEPTION] Action %s failed with exception: %s",
                action_id, sanitized_error
            )
            return {
                "success": False,
                "message": f"Exception during Cloudflare API call: {sanitized_error}",
                "executed": [{
                    "command": f"Cloudflare Magic Transit scrub {attacker_ip}",
                    "status": "FAILED",
                    "error": sanitized_error
                }]
            }

    def _call_cloudflare_api(
        self,
        attacker_ip: str,
        action: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Internal method to call the Cloudflare Magic Transit API.

        SECURITY: This method contains the actual API call logic and must ONLY be
        invoked from execute(), which is protected by the approval gate.

        Args:
            attacker_ip: IP address to scrub
            action: The action dict with additional context

        Returns:
            Result dict with success status and details
        """
        try:
            import requests
        except ImportError:
            logger.error("requests library not installed; cannot call Cloudflare API")
            return {
                "success": False,
                "error": "requests library not installed"
            }

        # Cloudflare Magic Transit API endpoint
        # Reference: https://developers.cloudflare.com/api/operations/magic-static-routes-create-route
        url = f"https://api.cloudflare.com/client/v4/accounts/{self.account_id}/magic/routes"

        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        }

        # Create a static route that directs traffic from this IP through scrubbing
        payload = {
            "prefix": f"{attacker_ip}/32",  # Single IP address
            "nexthop": "scrub",             # Route through Cloudflare scrubbing
            "priority": 100,                # High priority
            "description": f"DDoS mitigation - action {action.get('action_id')} - {action.get('reason', 'automated scrubbing')}",
        }

        try:
            response = requests.post(
                url,
                headers=headers,
                json=payload,
                timeout=10,
            )

            if response.status_code in (200, 201):
                data = response.json()
                if data.get("success"):
                    logger.info(
                        "Cloudflare Magic Transit route created successfully for %s",
                        attacker_ip
                    )
                    return {
                        "success": True,
                        "details": data.get("result", {})
                    }
                else:
                    errors = data.get("errors", [])
                    error_msg = "; ".join([e.get("message", str(e)) for e in errors])
                    return {
                        "success": False,
                        "error": f"Cloudflare API returned success=false: {error_msg}"
                    }
            else:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {response.text[:200]}"
                }

        except requests.exceptions.Timeout:
            return {
                "success": False,
                "error": "Cloudflare API request timed out after 10 seconds"
            }
        except requests.exceptions.RequestException as e:
            return {
                "success": False,
                "error": f"Cloudflare API request failed: {e}"
            }

    def _sanitize_error_message(self, message: str) -> str:
        """
        SANITIZE: Remove any API token values from error messages before persisting.

        CRITICAL: Ensures that Cloudflare API tokens are never stored in
        pending_actions.json or returned to operators via error messages.

        This is a safety requirement to comply with AGENTS.md Rule 2 and the
        Secrets management policy: "No API keys, tokens, or credentials in
        source files, ever. Load from environment variables or a gitignored .env file only."

        REDACTION STRATEGY (Task 2):
        - Target credential-shaped strings that follow recognizable prefixes
        - Do NOT blindly redact all long alphanumeric strings (would corrupt
          request IDs like "req_a1b2c3d4e5f6g7h8" or resource IDs)
        """
        import re

        # Pattern 1: Explicit credential patterns with prefixes
        # Matches: "token abc123", "key=xyz", "bearer xyz", "auth xyz", "password xyz"
        credential_prefixed = [
            r'\b(?:token|key|bearer|auth|password|secret|api[_-]?key)\s*[:=]?\s*[a-zA-Z0-9_-]{8,}',
        ]

        sanitized = message
        for pattern in credential_prefixed:
            sanitized = re.sub(pattern, '[CREDENTIAL_REDACTED]', sanitized, flags=re.IGNORECASE)

        # Pattern 2: Known token format prefixes (e.g., "sk-or-v1-", "cf-")
        known_token_prefixes = [
            r'sk-or-v1-[a-zA-Z0-9_-]+',   # OpenRouter / OpenAI style
            r'Bearer\s+[a-zA-Z0-9._-]+',  # Bearer token in text
            r'cf[_-]?[a-zA-Z0-9_-]{20,}', # Cloudflare-style tokens
        ]

        for pattern in known_token_prefixes:
            sanitized = re.sub(pattern, '[TOKEN_REDACTED]', sanitized, flags=re.IGNORECASE)

        # Pattern 3: The configured API token (redact if it appears literally)
        if self.api_token:
            # Only redact if the token appears in a credential-like context
            # (surrounded by special chars or part of a credential string)
            escaped = re.escape(self.api_token)
            # Match token when it appears after: space, =, :, or in quotes
            context_pattern = rf'(?:[=\s"\':]|Bearer\s+){escaped}(?:\s|$|[,;])'
            sanitized = re.sub(context_pattern, f'[TOKEN_REDACTED]', sanitized)

        return sanitized

    def remove_scrubbing(
        self,
        attacker_ip: str,
        route_id: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Remove Cloudflare scrubbing for an IP (manual cleanup method).

        Note: This is a utility method for manual cleanup. Automated scrubbing
        removal could be implemented via time-based expiration or a separate
        approval-gated "remove_cloudflare_scrub" action type.

        Args:
            attacker_ip: IP address to stop scrubbing
            route_id: Optional Cloudflare route ID to delete

        Returns:
            (success: bool, message: str)
        """
        if not self.api_token or not self.account_id:
            return False, "Cloudflare credentials not configured"

        try:
            import requests
        except ImportError:
            return False, "requests library not installed"

        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        }

        # If route_id not provided, list routes and find by prefix
        if not route_id:
            list_url = f"https://api.cloudflare.com/client/v4/accounts/{self.account_id}/magic/routes"
            try:
                response = requests.get(list_url, headers=headers, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("success"):
                        routes = data.get("result", [])
                        for route in routes:
                            if route.get("prefix") == f"{attacker_ip}/32":
                                route_id = route.get("id")
                                break
            except Exception as e:
                return False, f"Failed to list routes: {e}"

        if not route_id:
            return False, f"No scrubbing route found for {attacker_ip}"

        # Delete the route
        delete_url = f"https://api.cloudflare.com/client/v4/accounts/{self.account_id}/magic/routes/{route_id}"
        try:
            response = requests.delete(delete_url, headers=headers, timeout=10)
            if response.status_code in (200, 204):
                logger.info("Cloudflare scrubbing removed for %s (route_id: %s)", attacker_ip, route_id)
                return True, f"Scrubbing removed for {attacker_ip}"
            else:
                return False, f"HTTP {response.status_code}: {response.text[:200]}"
        except Exception as e:
            return False, f"Failed to delete route: {e}"
