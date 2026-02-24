"""Evidence management commands: lock, unlock, register, list, verify, log.

Subcommand group:
  aiir evidence register <path> [--description]
  aiir evidence list
  aiir evidence verify
  aiir evidence log [--path <filter>]
  aiir evidence lock
  aiir evidence unlock

Legacy aliases (backward compat):
  aiir register-evidence <path>
  aiir lock-evidence
  aiir unlock-evidence
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

from aiir_cli.approval_auth import require_tty_confirmation
from aiir_cli.case_io import get_case_dir


def cmd_evidence(args, identity: dict) -> None:
    """Handle evidence subcommands."""
    action = getattr(args, "evidence_action", None)
    if action == "register":
        cmd_register_evidence(args, identity)
    elif action == "list":
        cmd_list_evidence(args, identity)
    elif action == "verify":
        cmd_verify_evidence(args, identity)
    elif action == "log":
        cmd_evidence_log(args, identity)
    elif action == "lock":
        cmd_lock_evidence(args, identity)
    elif action == "unlock":
        cmd_unlock_evidence(args, identity)
    else:
        print("Usage: aiir evidence {register|list|verify|log|lock|unlock}", file=sys.stderr)
        sys.exit(1)


def cmd_lock_evidence(args, identity: dict) -> None:
    """Lock evidence directory by making all files read-only (chmod 444)."""
    case_dir = get_case_dir(getattr(args, "case", None))
    evidence_dir = case_dir / "evidence"

    if not evidence_dir.exists():
        print(f"Evidence directory not found: {evidence_dir}", file=sys.stderr)
        sys.exit(1)

    count = 0
    errors = 0
    for path in evidence_dir.rglob("*"):
        if path.is_file():
            try:
                path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)  # 444
                count += 1
            except OSError as e:
                print(f"  Warning: could not chmod {path}: {e}", file=sys.stderr)
                errors += 1

    # Also make the directory itself read-only
    try:
        evidence_dir.chmod(stat.S_IRUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)  # 555
    except OSError as e:
        print(f"  Warning: could not chmod evidence directory: {e}", file=sys.stderr)
        errors += 1

    _log_evidence_action(case_dir, "lock", f"Locked {count} files", identity)
    print(f"Locked evidence directory: {count} file(s) set to read-only (444)")
    if errors:
        print(f"  {errors} file(s) could not be locked (see warnings above)")
    print(f"Directory set to 555 (no writes)")


def cmd_unlock_evidence(args, identity: dict) -> None:
    """Unlock evidence directory for new files."""
    case_dir = get_case_dir(getattr(args, "case", None))
    evidence_dir = case_dir / "evidence"

    if not evidence_dir.exists():
        print(f"Evidence directory not found: {evidence_dir}", file=sys.stderr)
        sys.exit(1)

    # Confirm via /dev/tty (blocks AI-via-Bash from piping "y")
    print(f"WARNING: Unlocking evidence directory allows writes.")
    print(f"  Path: {evidence_dir}")
    if not require_tty_confirmation("Unlock evidence directory? [y/N]: "):
        print("Cancelled.")
        return

    # Restore write permissions on directory
    try:
        evidence_dir.chmod(stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)  # 755
    except OSError as e:
        print(f"Failed to unlock evidence directory: {e}", file=sys.stderr)
        sys.exit(1)

    _log_evidence_action(case_dir, "unlock", "Unlocked evidence directory", identity)
    print("Evidence directory unlocked (755). Files remain read-only.")
    print("Use 'aiir evidence register <path>' after adding new files.")


def cmd_register_evidence(args, identity: dict) -> None:
    """Register evidence file: hash + chmod 444."""
    case_dir = get_case_dir(getattr(args, "case", None))
    evidence_path = Path(args.path)

    if not evidence_path.exists():
        print(f"File not found: {args.path}", file=sys.stderr)
        sys.exit(1)

    # Validate path is within case directory
    try:
        resolved = evidence_path.resolve()
        case_resolved = case_dir.resolve()
        if not str(resolved).startswith(str(case_resolved) + os.sep) and resolved != case_resolved:
            print(f"Error: evidence path must be within the case directory.", file=sys.stderr)
            print(f"  Evidence file:     {resolved}", file=sys.stderr)
            print(f"  Case evidence dir: {case_dir / 'evidence'}", file=sys.stderr)
            print(f"  Fix: copy the file into the evidence directory first, then register it.", file=sys.stderr)
            sys.exit(1)
    except OSError as e:
        print(f"Failed to resolve evidence path: {e}", file=sys.stderr)
        sys.exit(1)

    # Compute SHA256
    try:
        sha256 = hashlib.sha256()
        with open(evidence_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        file_hash = sha256.hexdigest()
    except OSError as e:
        print(f"Failed to read evidence file for hashing: {e}", file=sys.stderr)
        sys.exit(1)

    # Set read-only
    try:
        evidence_path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)  # 444
    except OSError as e:
        print(f"Warning: could not set evidence file to read-only: {e}", file=sys.stderr)

    # Record in evidence registry
    reg_file = case_dir / "evidence.json"
    try:
        if reg_file.exists():
            registry = json.loads(reg_file.read_text())
        else:
            registry = {"files": []}
    except json.JSONDecodeError as e:
        print(f"Warning: evidence registry is corrupt ({e}), starting fresh.", file=sys.stderr)
        registry = {"files": []}
    except OSError as e:
        print(f"Warning: could not read evidence registry ({e}), starting fresh.", file=sys.stderr)
        registry = {"files": []}

    entry = {
        "path": str(evidence_path.resolve()),
        "sha256": file_hash,
        "description": args.description,
        "registered_at": datetime.now(timezone.utc).isoformat(),
        "registered_by": identity.get("examiner", identity.get("analyst", "")),
    }
    registry["files"].append(entry)

    try:
        from aiir_cli.case_io import _atomic_write
        _atomic_write(reg_file, json.dumps(registry, indent=2, default=str))
    except OSError as e:
        print(f"Failed to write evidence registry: {e}", file=sys.stderr)
        sys.exit(1)

    # Log access
    _log_evidence_action(case_dir, "register", str(evidence_path), identity, sha256=file_hash)

    print(f"Registered: {evidence_path}")
    print(f"  SHA256: {file_hash}")
    print(f"  Permissions: 444 (read-only)")


def _log_evidence_action(case_dir: Path, action: str, detail: str,
                         identity: dict, **extra) -> None:
    """Write evidence action to access log."""
    try:
        log_file = case_dir / "evidence_access.jsonl"
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "detail": detail,
            "examiner": identity.get("examiner", identity.get("analyst", "")),
            "os_user": identity["os_user"],
        }
        entry.update(extra)
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()
            os.fsync(f.fileno())
    except OSError as e:
        print(f"WARNING: failed to write evidence access log: {e}", file=sys.stderr)


def cmd_list_evidence(args, identity: dict) -> None:
    """List registered evidence files from evidence.json."""
    case_dir = get_case_dir(getattr(args, "case", None))
    reg_file = case_dir / "evidence.json"

    if not reg_file.exists():
        print("No evidence registry found.")
        return

    try:
        registry = json.loads(reg_file.read_text())
    except (json.JSONDecodeError, OSError) as e:
        print(f"Failed to read evidence registry: {e}", file=sys.stderr)
        sys.exit(1)

    files = registry.get("files", [])
    if not files:
        print("No evidence files registered.")
        return

    print(f"{'#':<4} {'SHA256':<20} {'Registered By':<15} Path")
    print("-" * 80)
    for i, entry in enumerate(files, 1):
        sha = entry.get("sha256", "?")[:16] + "..."
        by = entry.get("registered_by", "?")
        path = entry.get("path", "?")
        print(f"{i:<4} {sha:<20} {by:<15} {path}")
        if entry.get("description"):
            print(f"     Description: {entry['description']}")

    print(f"\n{len(files)} evidence file(s) registered")


def cmd_verify_evidence(args, identity: dict) -> None:
    """Re-hash registered evidence files and report modifications."""
    case_dir = get_case_dir(getattr(args, "case", None))
    reg_file = case_dir / "evidence.json"

    if not reg_file.exists():
        print("No evidence registry found.")
        return

    try:
        registry = json.loads(reg_file.read_text())
    except (json.JSONDecodeError, OSError) as e:
        print(f"Failed to read evidence registry: {e}", file=sys.stderr)
        sys.exit(1)

    files = registry.get("files", [])
    if not files:
        print("No evidence files registered.")
        return

    verified = 0
    modified = 0
    missing = 0
    errors = 0

    print(f"{'Status':<12} {'Path'}")
    print("-" * 70)

    for entry in files:
        path = Path(entry.get("path", ""))
        expected_hash = entry.get("sha256", "")

        if not path.exists():
            print(f"{'MISSING':<12} {path}")
            missing += 1
            continue

        try:
            sha256 = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            actual_hash = sha256.hexdigest()
        except OSError as e:
            print(f"{'ERROR':<12} {path} ({e})")
            errors += 1
            continue

        if actual_hash == expected_hash:
            print(f"{'OK':<12} {path}")
            verified += 1
        else:
            print(f"{'MODIFIED':<12} {path}")
            print(f"             Expected: {expected_hash}")
            print(f"             Actual:   {actual_hash}")
            modified += 1

    print(f"\n{verified} verified, {modified} MODIFIED, {missing} missing, {errors} errors")
    if modified:
        print("ALERT: Evidence files have been modified since registration.")
        sys.exit(2)


def cmd_evidence_log(args, identity: dict) -> None:
    """Show evidence access log entries."""
    case_dir = get_case_dir(getattr(args, "case", None))
    log_file = case_dir / "evidence_access.jsonl"

    if not log_file.exists():
        print("No evidence access log found.")
        return

    path_filter = getattr(args, "path_filter", None)

    try:
        log_text = log_file.read_text()
    except OSError as e:
        print(f"Failed to read evidence access log: {e}", file=sys.stderr)
        sys.exit(1)

    entries = []
    for line in log_text.strip().split("\n"):
        if not line:
            continue
        try:
            entry = json.loads(line)
            entries.append(entry)
        except json.JSONDecodeError:
            continue

    if path_filter:
        entries = [e for e in entries if path_filter in e.get("detail", "")]

    if not entries:
        print("No evidence access log entries found.")
        return

    print(f"{'Timestamp':<22} {'Action':<10} {'Examiner':<12} Detail")
    print("-" * 80)
    for e in entries:
        ts = e.get("ts", "?")[:19]
        action = e.get("action", "?")
        examiner = e.get("examiner", "?")
        detail = e.get("detail", "")
        if len(detail) > 40:
            detail = detail[:37] + "..."
        print(f"{ts:<22} {action:<10} {examiner:<12} {detail}")

    print(f"\n{len(entries)} entries")
