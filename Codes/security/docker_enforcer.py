# -*- coding: utf-8 -*-
"""
Docker Enforcer — proposes Docker container isolation actions.

SAFETY: This module NEVER executes docker exec/stop/disconnect commands
directly. All proposed actions are written to the shared pending-actions
store in ai_threat_analyzer.py and require explicit human approval.
"""
import logging

from security.ai_threat_analyzer import _propose_action

logger = logging.getLogger("DockerEnforcer")


class DockerEnforcer:
    """
    Proposes Docker container isolation and enforcement for DDoS attacker containers.
    All actions are proposed only — execution requires human approval via
    approve_action() from ai_threat_analyzer.
    """

    @staticmethod
    def block_attacker_container(attacker_ip, victim_ip="0.0.0.0"):
        """
        Propose blocking an attacker's Docker container.

        Previously this method directly ran 'docker exec iptables' and
        'docker network disconnect'. Now it writes a pending action and
        returns the action_id. The actual command is only executed when
        a human calls approve_action(action_id).

        Returns (action_id: str, message: str).
        """
        proposed_commands = [
            f"docker exec <container_id> iptables -A OUTPUT -d {victim_ip} -j DROP",
            f"docker network disconnect bridge <container_id>",
        ]

        action_id = _propose_action(
            action_type="DOCKER_BLOCK",
            attacker_ip=attacker_ip,
            victim_ip=victim_ip,
            reason=(
                f"Docker enforcer: block container associated with attacker "
                f"{attacker_ip} targeting {victim_ip}"
            ),
            commands=proposed_commands,
            source="docker_enforcer",
        )

        logger.info(
            "📋 [DOCKER ENFORCER] Proposed container block for %s → %s (action_id: %s). "
            "Awaiting human approval.",
            attacker_ip, victim_ip, action_id
        )

        return action_id, f"Proposed Docker block action {action_id} (pending approval)"
