# -*- coding: utf-8 -*-
"""
Mitigation Engine CLI — Operator Interface for Human-in-the-Loop Approval.

Commands:
  python -m src.mitigation.cli list                  — List all pending mitigation actions
  python -m src.mitigation.cli show <action_id>       — Display details of an action
  python -m src.mitigation.cli approve <action_id>    — Approve and execute a pending action
  python -m src.mitigation.cli reject <action_id>     — Reject a pending action
  python -m src.mitigation.cli log                   — Display chronological action log
"""
import sys
import argparse
import datetime
from typing import Optional

from src.mitigation.manager import get_manager


def _format_time(ts: Optional[float]) -> str:
    if not ts:
        return "-"
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def cmd_list(args):
    """List all pending actions."""
    manager = get_manager(args.config)
    pending = manager.get_pending()

    if not pending:
        print("\n[INFO] No pending mitigation actions requiring approval.")
        return 0

    print(f"\n{'='*90}")
    print(f" PENDING MITIGATION ACTIONS ({len(pending)}) — HUMAN APPROVAL REQUIRED")
    print(f"{'='*90}")
    print(f"{'ACTION ID':<10} {'TYPE':<16} {'ATTACKER IP':<16} {'VICTIM IP':<16} {'CONF':<6} {'PROPOSED AT':<20}")
    print(f"{'-'*90}")

    for aid, action in pending.items():
        conf_str = f"{action.get('confidence', 0.0):.2f}" if action.get("confidence") is not None else "N/A"
        time_str = _format_time(action.get("proposed_at"))
        print(
            f"{aid:<10} "
            f"{action.get('action_type', 'UNKNOWN')[:15]:<16} "
            f"{action.get('attacker_ip', 'UNKNOWN')[:15]:<16} "
            f"{action.get('victim_ip', 'UNKNOWN')[:15]:<16} "
            f"{conf_str:<6} "
            f"{time_str:<20}"
        )
    print(f"{'='*90}\n")
    return 0


def cmd_show(args):
    """Show details of a specific action."""
    manager = get_manager(args.config)
    action = manager.get_action(args.action_id)

    if not action:
        print(f"\n[ERROR] Action ID '{args.action_id}' not found.", file=sys.stderr)
        return 1

    print(f"\n{'='*70}")
    print(f" ACTION DETAILS: {action.get('action_id')}")
    print(f"{'='*70}")
    print(f"  Status        : {action.get('status')}")
    print(f"  Type          : {action.get('action_type')}")
    print(f"  Attacker IP   : {action.get('attacker_ip')}")
    print(f"  Victim IP     : {action.get('victim_ip')}")
    print(f"  Confidence    : {action.get('confidence')}")
    print(f"  Source        : {action.get('source')}")
    print(f"  Proposed At   : {_format_time(action.get('proposed_at'))}")
    print(f"  Approved At   : {_format_time(action.get('approved_at'))}")
    print(f"  Rejected At   : {_format_time(action.get('rejected_at'))}")
    print(f"  Approver      : {action.get('approver') or '-'}")
    print(f"  Reason        : {action.get('reason')}")
    print(f"  Proposed Cmds :")
    for cmd in action.get("proposed_commands", []):
        print(f"    - {cmd}")
    if action.get("execution_result"):
        print(f"  Execution Res : {action.get('execution_result')}")
    print(f"{'='*70}\n")
    return 0


def cmd_approve(args):
    """Approve and execute a pending action."""
    manager = get_manager(args.config)
    success, message, action = manager.approve(args.action_id, approver=args.user)

    if success:
        print(f"\n[SUCCESS] Action {args.action_id} APPROVED and EXECUTED.")
        print(f"Details: {message}\n")
        return 0
    else:
        print(f"\n[FAILED] Could not approve action {args.action_id}: {message}", file=sys.stderr)
        return 1


def cmd_reject(args):
    """Reject a pending action."""
    manager = get_manager(args.config)
    success, message, action = manager.reject(args.action_id, reason=args.reason, rejecter=args.user)

    if success:
        print(f"\n[SUCCESS] Action {args.action_id} REJECTED.")
        return 0
    else:
        print(f"\n[FAILED] Could not reject action {args.action_id}: {message}", file=sys.stderr)
        return 1


def cmd_log(args):
    """Display chronological history."""
    manager = get_manager(args.config)
    log = manager.get_action_log()

    if not log:
        print("\n[INFO] Action log is empty.")
        return 0

    print(f"\n{'='*95}")
    print(f" CHRONOLOGICAL MITIGATION ACTION AUDIT LOG ({len(log)} entries)")
    print(f"{'='*95}")
    print(f"{'ACTION ID':<10} {'STATUS':<10} {'TYPE':<16} {'ATTACKER IP':<16} {'VICTIM IP':<16} {'TIMESTAMP':<20}")
    print(f"{'-'*95}")

    for action in log:
        time_str = _format_time(action.get("proposed_at"))
        print(
            f"{action.get('action_id', ''):<10} "
            f"{action.get('status', ''):<10} "
            f"{action.get('action_type', '')[:15]:<16} "
            f"{action.get('attacker_ip', '')[:15]:<16} "
            f"{action.get('victim_ip', '')[:15]:<16} "
            f"{time_str:<20}"
        )
    print(f"{'='*95}\n")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m src.mitigation.cli",
        description="CyberShield Mitigation Approval CLI — Human-in-the-Loop Safety Gate",
    )
    parser.add_argument("--config", "-c", help="Path to pending_actions.json storage file", default=None)
    parser.add_argument("--user", "-u", help="Operator username for audit log", default="cli_operator")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # list / pending
    subparsers.add_parser("list", help="List all pending actions")
    subparsers.add_parser("pending", help="Alias for list")

    # show
    show_p = subparsers.add_parser("show", help="Show details of a specific action")
    show_p.add_argument("action_id", help="Action ID to inspect")

    # approve
    app_p = subparsers.add_parser("approve", help="Approve and execute a pending action")
    app_p.add_argument("action_id", help="Action ID to approve")

    # reject
    rej_p = subparsers.add_parser("reject", help="Reject a pending action without execution")
    rej_p.add_argument("action_id", help="Action ID to reject")
    rej_p.add_argument("--reason", "-r", help="Reason for rejection", default="")

    # log
    subparsers.add_parser("log", help="Show full action history")

    parsed = parser.parse_args(argv)

    if parsed.command in ("list", "pending"):
        return cmd_list(parsed)
    elif parsed.command == "show":
        return cmd_show(parsed)
    elif parsed.command == "approve":
        return cmd_approve(parsed)
    elif parsed.command == "reject":
        return cmd_reject(parsed)
    elif parsed.command == "log":
        return cmd_log(parsed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
