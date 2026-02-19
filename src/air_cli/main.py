"""AIR CLI entry point.

Human-only actions that the LLM orchestrator cannot bypass:
- approve/reject findings and timeline events (/dev/tty + optional PIN)
- evidence management (lock/unlock)
- forensic command execution with audit
- analyst identity configuration
"""

from __future__ import annotations

import argparse
import sys

from air_cli.identity import get_analyst_identity, warn_if_unconfigured
from air_cli.commands.approve import cmd_approve
from air_cli.commands.reject import cmd_reject
from air_cli.commands.review import cmd_review
from air_cli.commands.execute import cmd_exec
from air_cli.commands.evidence import cmd_lock_evidence, cmd_unlock_evidence, cmd_register_evidence
from air_cli.commands.config import cmd_config


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="air",
        description="Applied IR — forensic investigation CLI",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s 0.1.0")
    parser.add_argument("--case", help="Case ID (overrides active case)")

    sub = parser.add_subparsers(dest="command", help="Available commands")

    # approve
    p_approve = sub.add_parser("approve", help="Approve staged findings/timeline events")
    p_approve.add_argument("ids", nargs="*", help="Finding/event IDs to approve (omit for interactive review)")
    p_approve.add_argument("--analyst", help="Override analyst identity")

    # reject
    p_reject = sub.add_parser("reject", help="Reject staged findings/timeline events")
    p_reject.add_argument("ids", nargs="+", help="Finding/event IDs to reject")
    p_reject.add_argument("--reason", default="", help="Reason for rejection (optional)")
    p_reject.add_argument("--analyst", help="Override analyst identity")

    # review
    p_review = sub.add_parser("review", help="Review case status and audit trail")
    p_review.add_argument("--audit", action="store_true", help="Show audit log")
    p_review.add_argument("--evidence", action="store_true", help="Show evidence integrity")
    p_review.add_argument("--findings", action="store_true", help="Show findings summary table")
    p_review.add_argument("--detail", action="store_true", help="Show full detail (with --findings or --timeline)")
    p_review.add_argument("--verify", action="store_true", help="Cross-check findings against approval records")
    p_review.add_argument("--iocs", action="store_true", help="Extract IOCs from findings grouped by status")
    p_review.add_argument("--timeline", action="store_true", help="Show timeline events")
    p_review.add_argument("--limit", type=int, default=50, help="Limit entries shown")

    # exec
    p_exec = sub.add_parser("exec", help="Execute forensic command with audit trail")
    p_exec.add_argument("--purpose", required=True, help="Purpose of command execution")
    p_exec.add_argument("cmd", nargs=argparse.REMAINDER, help="Command to execute (after --)")

    # lock-evidence / unlock-evidence
    sub.add_parser("lock-evidence", help="Set evidence directory to read-only (bind mount)")
    sub.add_parser("unlock-evidence", help="Unlock evidence directory for new files")

    # register-evidence
    p_reg = sub.add_parser("register-evidence", help="Register evidence file (hash + chmod 444)")
    p_reg.add_argument("path", help="Path to evidence file")
    p_reg.add_argument("--description", default="", help="Description of evidence")

    # config
    p_config = sub.add_parser("config", help="Configure AIR settings")
    p_config.add_argument("--analyst", help="Set analyst identity")
    p_config.add_argument("--show", action="store_true", help="Show current configuration")
    p_config.add_argument("--setup-pin", action="store_true", help="Set approval PIN for current analyst")
    p_config.add_argument("--reset-pin", action="store_true", help="Reset approval PIN (requires current PIN)")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    # Identity check on every command
    identity = get_analyst_identity(getattr(args, "analyst", None))
    warn_if_unconfigured(identity)

    dispatch = {
        "approve": cmd_approve,
        "reject": cmd_reject,
        "review": cmd_review,
        "exec": cmd_exec,
        "lock-evidence": cmd_lock_evidence,
        "unlock-evidence": cmd_unlock_evidence,
        "register-evidence": cmd_register_evidence,
        "config": cmd_config,
    }

    handler = dispatch.get(args.command)
    if handler:
        handler(args, identity)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
