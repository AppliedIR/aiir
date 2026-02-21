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
from aiir_cli.identity import get_examiner_identity, warn_if_unconfigured
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
    p_approve.add_argument("--examiner", dest="examiner_override", help="Override examiner identity")
    p_approve.add_argument("--analyst", dest="examiner_override", help="(deprecated, use --examiner)")
    p_approve.add_argument("--note", help="Add examiner note when approving specific IDs")
    p_approve.add_argument("--edit", action="store_true", help="Open in $EDITOR before approving")
    p_approve.add_argument("--interpretation", help="Override interpretation field")
    p_approve.add_argument("--by", help="Filter items by creator examiner (interactive mode)")
    p_approve.add_argument("--findings-only", action="store_true", help="Review only findings")
    p_approve.add_argument("--timeline-only", action="store_true", help="Review only timeline events")

    # reject
    p_reject = sub.add_parser("reject", help="Reject staged findings/timeline events")
    p_reject.add_argument("ids", nargs="+", help="Finding/event IDs to reject")
    p_reject.add_argument("--reason", default="", help="Reason for rejection (optional)")
    p_reject.add_argument("--examiner", dest="examiner_override", help="Override examiner identity")
    p_reject.add_argument("--analyst", dest="examiner_override", help="(deprecated, use --examiner)")

    # case (init + join)
    p_case = sub.add_parser("case", help="Case management: init, join")
    case_sub = p_case.add_subparsers(dest="case_action", help="Case actions")
    p_case_init = case_sub.add_parser("init", help="Initialize a new case")
    p_case_init.add_argument("name", help="Case name")
    p_case_init.add_argument("--description", default="", help="Case description")
    p_case_init.add_argument("--collaborative", "-c", action="store_true", help="Create in collaborative mode")
    p_case_join = case_sub.add_parser("join", help="Join an existing case as a new examiner")
    p_case_join.add_argument("--case-id", required=True, help="Case ID to join")
    p_case_join.add_argument("--examiner", help="Examiner slug (defaults to current identity)")

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
    p_review.add_argument("--status", help="Filter by status (DRAFT/APPROVED/REJECTED)")
    p_review.add_argument("--start", help="Start date filter (ISO format, e.g. 2026-01-01)")
    p_review.add_argument("--end", help="End date filter (ISO format, e.g. 2026-12-31)")
    p_review.add_argument("--type", help="Filter by event type (with --timeline)")
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
    setup_sub = p_setup.add_subparsers(dest="setup_action")
    setup_sub.add_parser("test", help="Test connectivity to all detected MCP servers")

    p_client = setup_sub.add_parser("client", help="Configure LLM client for AIIR endpoints")
    p_client.add_argument("--client", choices=["claude-code", "claude-desktop", "cursor", "librechat"], help="Target LLM client")
    p_client.add_argument("--sift", help="SIFT gateway URL (e.g., http://127.0.0.1:4508)")
    p_client.add_argument("--windows", help="Windows wintools-mcp endpoint (e.g., 192.168.1.20:4624)")
    p_client.add_argument("--remnux", help="REMnux endpoint (e.g., 192.168.1.30:3000)")
    p_client.add_argument("--examiner", help="Examiner identity")
    p_client.add_argument("--no-zeltser", action="store_true", help="Exclude Zeltser IR Writing MCP")
    p_client.add_argument("--no-mslearn", action="store_true", help="Exclude Microsoft Learn MCP")
    p_client.add_argument("-y", "--yes", action="store_true", help="Accept defaults, no prompts")

    # sync
    p_sync = sub.add_parser("sync", help="Multi-examiner sync: export/import contribution bundles")
    sync_sub = p_sync.add_subparsers(dest="sync_action", help="Sync actions")
    p_sync_export = sync_sub.add_parser("export", help="Export contributions to bundle file")
    p_sync_export.add_argument("--file", required=True, help="Output file path")
    p_sync_import = sync_sub.add_parser("import", help="Import contributions from bundle file")
    p_sync_import.add_argument("--file", required=True, help="Input file path")

    # config
    p_config = sub.add_parser("config", help="Configure AIIR settings")
    p_config.add_argument("--examiner", help="Set examiner identity")
    p_config.add_argument("--analyst", dest="examiner", help="(deprecated, use --examiner)")
    p_config.add_argument("--show", action="store_true", help="Show current configuration")
    p_config.add_argument("--setup-pin", action="store_true", help="Set approval PIN for current examiner")
    p_config.add_argument("--reset-pin", action="store_true", help="Reset approval PIN (requires current PIN)")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    # Identity check on every command
    # Support both --examiner and --analyst (deprecated) overrides
    flag_override = getattr(args, "examiner_override", None) or getattr(args, "analyst", None)
    identity = get_examiner_identity(flag_override)
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
        "case": _cmd_case,
    }

    handler = dispatch.get(args.command)
    if handler:
        handler(args, identity)
    else:
        parser.print_help()
        sys.exit(1)


def _cmd_case(args, identity: dict) -> None:
    """Handle case subcommands: init, join."""
    action = getattr(args, "case_action", None)
    if action == "init":
        _case_init(args, identity)
    elif action == "join":
        _case_join(args, identity)
    else:
        print("Usage: aiir case {init|join}", file=sys.stderr)
        sys.exit(1)


def _case_init(args, identity: dict) -> None:
    """Initialize a new case from CLI."""
    import json
    import os
    from datetime import datetime, timezone
    from pathlib import Path

    import yaml

    cases_dir = Path(os.environ.get("AIIR_CASES_DIR", "cases"))
    ts = datetime.now(timezone.utc)
    case_id = f"INC-{ts.strftime('%Y')}-{ts.strftime('%m%d%H%M%S')}"
    case_dir = cases_dir / case_id

    if case_dir.exists():
        print(f"Case directory already exists: {case_dir}", file=sys.stderr)
        sys.exit(1)

    examiner = identity["examiner"]
    if not examiner:
        print("Cannot initialize case: examiner identity is empty.", file=sys.stderr)
        sys.exit(1)

    collaborative = getattr(args, "collaborative", False)
    mode = "collaborative" if collaborative else "solo"

    # Create directory structure. If any step fails, report what was partially created.
    created_dirs: list[Path] = []
    try:
        case_dir.mkdir(parents=True)
        created_dirs.append(case_dir)
        for subdir in ("evidence", "extracted", "reports"):
            d = case_dir / subdir
            d.mkdir()
            created_dirs.append(d)

        exam_dir = case_dir / "examiners" / examiner
        exam_dir.mkdir(parents=True)
        created_dirs.append(exam_dir)
        audit_dir = exam_dir / "audit"
        audit_dir.mkdir()
        created_dirs.append(audit_dir)
    except OSError as e:
        print(f"Failed to create case directories: {e}", file=sys.stderr)
        if created_dirs:
            print(f"  Partially created directories: {', '.join(str(d) for d in created_dirs)}", file=sys.stderr)
        sys.exit(1)

    case_meta = {
        "case_id": case_id,
        "name": args.name,
        "description": getattr(args, "description", ""),
        "mode": mode,
        "status": "open",
        "examiner": examiner,
        "team": [examiner],
        "created": ts.isoformat(),
        "created_by": examiner,
    }

    try:
        with open(case_dir / "CASE.yaml", "w") as f:
            yaml.dump(case_meta, f, default_flow_style=False)
            f.flush()
            os.fsync(f.fileno())
    except (OSError, yaml.YAMLError) as e:
        print(f"Failed to write CASE.yaml: {e}", file=sys.stderr)
        print(f"  Directories were created at: {case_dir}", file=sys.stderr)
        sys.exit(1)

    try:
        for fname in ("findings.json", "timeline.json", "todos.json"):
            with open(exam_dir / fname, "w") as f:
                f.write("[]")
                f.flush()
                os.fsync(f.fileno())
        with open(exam_dir / "evidence.json", "w") as f:
            json.dump({"files": []}, f)
            f.flush()
            os.fsync(f.fileno())
    except OSError as e:
        print(f"Failed to write initial case files: {e}", file=sys.stderr)
        print(f"  Case directory partially initialized at: {case_dir}", file=sys.stderr)
        sys.exit(1)

    # Set active case pointer
    try:
        aiir_dir = Path(".aiir")
        aiir_dir.mkdir(exist_ok=True)
        with open(aiir_dir / "active_case", "w") as f:
            f.write(case_id)
    except OSError as e:
        # Non-fatal: case was created successfully, just can't set active pointer
        print(f"Warning: could not set active case pointer: {e}", file=sys.stderr)

    print(f"Case initialized: {case_id}")
    print(f"  Name: {args.name}")
    print(f"  Mode: {mode}")
    print(f"  Examiner: {examiner}")
    print(f"  Path: {case_dir}")


def _case_join(args, identity: dict) -> None:
    """Join an existing case as a new examiner."""
    import json
    import os
    from pathlib import Path

    import yaml

    case_id = args.case_id
    examiner = getattr(args, "examiner", None) or identity["examiner"]
    if not examiner:
        print("Cannot join case: examiner identity is empty.", file=sys.stderr)
        sys.exit(1)

    cases_dir = Path(os.environ.get("AIIR_CASES_DIR", "cases"))
    case_dir = cases_dir / case_id

    if not case_dir.exists():
        print(f"Case not found: {case_id}", file=sys.stderr)
        sys.exit(1)

    meta_file = case_dir / "CASE.yaml"
    try:
        with open(meta_file) as f:
            meta = yaml.safe_load(f) or {}
    except OSError as e:
        print(f"Failed to read CASE.yaml: {e}", file=sys.stderr)
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"CASE.yaml is corrupt or invalid YAML: {e}", file=sys.stderr)
        sys.exit(1)

    exam_dir = case_dir / "examiners" / examiner
    if exam_dir.exists():
        print(f"Examiner '{examiner}' already has a directory in case {case_id}")
    else:
        try:
            exam_dir.mkdir(parents=True)
            (exam_dir / "audit").mkdir()
            for fname in ("findings.json", "timeline.json", "todos.json"):
                with open(exam_dir / fname, "w") as f:
                    f.write("[]")
                    f.flush()
                    os.fsync(f.fileno())
            with open(exam_dir / "evidence.json", "w") as f:
                json.dump({"files": []}, f)
                f.flush()
                os.fsync(f.fileno())
        except OSError as e:
            print(f"Failed to create examiner directory: {e}", file=sys.stderr)
            sys.exit(1)

    # Add to team list
    if examiner not in meta.get("team", []):
        meta.setdefault("team", []).append(examiner)
        try:
            with open(meta_file, "w") as f:
                yaml.dump(meta, f, default_flow_style=False)
                f.flush()
                os.fsync(f.fileno())
        except (OSError, yaml.YAMLError) as e:
            print(f"Failed to update team list in CASE.yaml: {e}", file=sys.stderr)
            sys.exit(1)

    # Set active case pointer
    try:
        aiir_dir = Path(".aiir")
        aiir_dir.mkdir(exist_ok=True)
        with open(aiir_dir / "active_case", "w") as f:
            f.write(case_id)
    except OSError as e:
        # Non-fatal: join succeeded, just can't set active pointer
        print(f"Warning: could not set active case pointer: {e}", file=sys.stderr)

    print(f"Joined case {case_id} as examiner '{examiner}'")
    print(f"  Team: {', '.join(meta.get('team', []))}")


if __name__ == "__main__":
    main()
