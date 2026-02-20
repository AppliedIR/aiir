"""AIIR CLI entry point.

Human-only actions that the LLM orchestrator cannot bypass:
- approve/reject findings and timeline events (/dev/tty + optional PIN)
- evidence management (lock/unlock)
- forensic command execution with audit
- analyst identity configuration
"""

from __future__ import annotations

import argparse
import sys

from aiir_cli import __version__
from aiir_cli.identity import get_analyst_identity, warn_if_unconfigured
from aiir_cli.commands.approve import cmd_approve
from aiir_cli.commands.reject import cmd_reject
from aiir_cli.commands.review import cmd_review
from aiir_cli.commands.execute import cmd_exec
from aiir_cli.commands.evidence import cmd_lock_evidence, cmd_unlock_evidence, cmd_register_evidence
from aiir_cli.commands.config import cmd_config
from aiir_cli.commands.todo import cmd_todo
from aiir_cli.commands.setup import cmd_setup
from aiir_cli.commands.sync import cmd_sync


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aiir",
        description="Applied IR — forensic investigation CLI",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--case", help="Case ID (overrides active case)")

    sub = parser.add_subparsers(dest="command", help="Available commands")

    # approve
    p_approve = sub.add_parser("approve", help="Approve staged findings/timeline events")
    p_approve.add_argument("ids", nargs="*", help="Finding/event IDs to approve (omit for interactive review)")
    p_approve.add_argument("--analyst", help="Override analyst identity")
    p_approve.add_argument("--note", help="Add examiner note when approving specific IDs")
    p_approve.add_argument("--edit", action="store_true", help="Open in $EDITOR before approving")
    p_approve.add_argument("--interpretation", help="Override interpretation field")
    p_approve.add_argument("--by", help="Filter items by creator analyst (interactive mode)")
    p_approve.add_argument("--findings-only", action="store_true", help="Review only findings")
    p_approve.add_argument("--timeline-only", action="store_true", help="Review only timeline events")

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
    p_review.add_argument("--todos", action="store_true", help="Show TODO items")
    p_review.add_argument("--open", action="store_true", help="Show only open TODOs (with --todos)")
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

    # todo
    p_todo = sub.add_parser("todo", help="Manage investigation TODOs")
    todo_sub = p_todo.add_subparsers(dest="todo_action", help="TODO actions")

    # todo (no action = list)
    # Default (no subcommand) shows open list — handled by argparse dest=None
    p_todo.add_argument("--all", action="store_true", help="Show all TODOs including completed")
    p_todo.add_argument("--assignee", default="", help="Filter by assignee")

    p_todo_add = todo_sub.add_parser("add", help="Add a new TODO")
    p_todo_add.add_argument("description", help="TODO description")
    p_todo_add.add_argument("--assignee", default="", help="Assign to analyst")
    p_todo_add.add_argument("--priority", choices=["high", "medium", "low"], default="medium")
    p_todo_add.add_argument("--finding", action="append", help="Related finding ID (repeatable)")

    p_todo_complete = todo_sub.add_parser("complete", help="Mark TODO as completed")
    p_todo_complete.add_argument("todo_id", help="TODO ID (e.g., TODO-001)")

    p_todo_update = todo_sub.add_parser("update", help="Update a TODO")
    p_todo_update.add_argument("todo_id", help="TODO ID (e.g., TODO-001)")
    p_todo_update.add_argument("--note", help="Add a note")
    p_todo_update.add_argument("--assignee", help="Reassign")
    p_todo_update.add_argument("--priority", choices=["high", "medium", "low"], help="Change priority")

    # setup
    p_setup = sub.add_parser("setup", help="Interactive setup for all MCP servers")
    p_setup.add_argument("--force-reprompt", action="store_true", help="Force re-prompting for all values")
    p_setup.add_argument("--non-interactive", action="store_true", help="Skip interactive prompts")

    # sync
    p_sync = sub.add_parser("sync", help="Multi-examiner sync: export/import contribution bundles")
    sync_sub = p_sync.add_subparsers(dest="sync_action", help="Sync actions")
    p_sync_export = sync_sub.add_parser("export", help="Export contributions to bundle file")
    p_sync_export.add_argument("--file", required=True, help="Output file path")
    p_sync_import = sync_sub.add_parser("import", help="Import contributions from bundle file")
    p_sync_import.add_argument("--file", required=True, help="Input file path")

    # config
    p_config = sub.add_parser("config", help="Configure AIIR settings")
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
        "todo": cmd_todo,
        "setup": cmd_setup,
        "sync": cmd_sync,
    }

    handler = dispatch.get(args.command)
    if handler:
        handler(args, identity)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
