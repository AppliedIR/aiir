"""Execute forensic commands with case context and audit trail."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from aiir_cli.approval_auth import require_tty_confirmation
from aiir_cli.case_io import get_case_dir


def cmd_exec(args, identity: dict) -> None:
    """Execute a forensic command with audit logging."""
    case_dir = get_case_dir(getattr(args, "case", None))

    if not args.cmd:
        print("No command specified. Usage: aiir exec --purpose '...' -- <command>", file=sys.stderr)
        sys.exit(1)

    # Strip leading '--' if present
    cmd_parts = args.cmd
    if cmd_parts and cmd_parts[0] == "--":
        cmd_parts = cmd_parts[1:]

    if not cmd_parts:
        print("No command specified after '--'.", file=sys.stderr)
        sys.exit(1)

    command = " ".join(cmd_parts)
    purpose = args.purpose

    # Confirm execution via /dev/tty (blocks AI-via-Bash from piping "y")
    print(f"Case: {case_dir.name}")
    print(f"Purpose: {purpose}")
    print(f"Command: {command}")
    if not require_tty_confirmation("Execute? [y/N]: "):
        print("Cancelled.")
        return

    # Execute
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300,
            cwd=str(case_dir),
        )
        exit_code = result.returncode
        stdout = result.stdout
        stderr = result.stderr
    except subprocess.TimeoutExpired:
        exit_code = -1
        stdout = ""
        stderr = "Command timed out (300s)"
    except Exception as e:
        exit_code = -1
        stdout = ""
        stderr = str(e)

    # Display output
    if stdout:
        print(f"\n--- stdout ---\n{stdout[:10000]}")
    if stderr:
        print(f"\n--- stderr ---\n{stderr[:5000]}", file=sys.stderr)
    print(f"\nExit code: {exit_code}")

    # Write audit entry
    _log_exec(case_dir, command, purpose, exit_code, stdout, stderr, identity)
    print("(logged to audit trail)")


def _log_exec(case_dir: Path, command: str, purpose: str, exit_code: int,
              stdout: str, stderr: str, identity: dict) -> None:
    """Write execution record to audit trail."""
    log_file = case_dir / ".audit" / "exec.jsonl"
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "command": command,
        "purpose": purpose,
        "exit_code": exit_code,
        "stdout_lines": len(stdout.splitlines()),
        "stderr_lines": len(stderr.splitlines()),
        "analyst": identity["analyst"],
        "os_user": identity["os_user"],
    }
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    # Also append to ACTIONS.md
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    md_entry = f"### {ts}\n\n**Executed by:** {identity['analyst']} (via `aiir exec`)\n"
    md_entry += f"**Purpose:** {purpose}\n**Command:** `{command}`\n**Exit code:** {exit_code}\n\n---\n\n"
    with open(case_dir / "ACTIONS.md", "a") as f:
        f.write(md_entry)
