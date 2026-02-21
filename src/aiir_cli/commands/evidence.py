"""Evidence management commands: lock, unlock, register."""

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


def cmd_lock_evidence(args, identity: dict) -> None:
    """Lock evidence directory by making all files read-only (chmod 444)."""
    case_dir = get_case_dir(getattr(args, "case", None))
    evidence_dir = case_dir / "evidence"

    if not evidence_dir.exists():
        print(f"Evidence directory not found: {evidence_dir}", file=sys.stderr)
        sys.exit(1)

    count = 0
    for path in evidence_dir.rglob("*"):
        if path.is_file():
            path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)  # 444
            count += 1

    # Also make the directory itself read-only
    evidence_dir.chmod(stat.S_IRUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)  # 555

    _log_evidence_action(case_dir, "lock", f"Locked {count} files", identity)
    print(f"Locked evidence directory: {count} file(s) set to read-only (444)")
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
    evidence_dir.chmod(stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)  # 755

    _log_evidence_action(case_dir, "unlock", "Unlocked evidence directory", identity)
    print("Evidence directory unlocked (755). Files remain read-only.")
    print("Use 'aiir register-evidence <path>' after adding new files.")


def cmd_register_evidence(args, identity: dict) -> None:
    """Register evidence file: hash + chmod 444."""
    case_dir = get_case_dir(getattr(args, "case", None))
    evidence_path = Path(args.path)

    if not evidence_path.exists():
        print(f"File not found: {args.path}", file=sys.stderr)
        sys.exit(1)

    # Compute SHA256
    sha256 = hashlib.sha256()
    with open(evidence_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    file_hash = sha256.hexdigest()

    # Set read-only
    evidence_path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)  # 444

    # Record in evidence registry
    from aiir_cli.case_io import _examiner_dir
    exam_dir = _examiner_dir(case_dir)
    exam_dir.mkdir(parents=True, exist_ok=True)
    reg_file = exam_dir / "evidence.json"
    if reg_file.exists():
        registry = json.loads(reg_file.read_text())
    else:
        registry = {"files": []}

    entry = {
        "path": str(evidence_path.resolve()),
        "sha256": file_hash,
        "description": args.description,
        "registered_at": datetime.now(timezone.utc).isoformat(),
        "registered_by": identity.get("examiner", identity.get("analyst", "")),
    }
    registry["files"].append(entry)

    with open(reg_file, "w") as f:
        json.dump(registry, f, indent=2, default=str)
        f.flush()
        os.fsync(f.fileno())

    # Log access
    _log_evidence_action(case_dir, "register", str(evidence_path), identity, sha256=file_hash)

    print(f"Registered: {evidence_path}")
    print(f"  SHA256: {file_hash}")
    print(f"  Permissions: 444 (read-only)")


def _log_evidence_action(case_dir: Path, action: str, detail: str,
                         identity: dict, **extra) -> None:
    """Write evidence action to access log."""
    from aiir_cli.case_io import _examiner_dir
    exam_dir = _examiner_dir(case_dir)
    exam_dir.mkdir(parents=True, exist_ok=True)
    log_file = exam_dir / "evidence_access.jsonl"
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
