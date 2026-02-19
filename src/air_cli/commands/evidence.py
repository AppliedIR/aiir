"""Evidence management commands: lock, unlock, register."""

from __future__ import annotations

from air_cli.case_io import get_case_dir


def cmd_lock_evidence(args, identity: dict) -> None:
    """Lock evidence directory (read-only bind mount)."""
    case_dir = get_case_dir(getattr(args, "case", None))
    # TODO: implement bind mount + remount read-only
    print(f"lock-evidence for case at: {case_dir}")
    print("(not yet implemented)")


def cmd_unlock_evidence(args, identity: dict) -> None:
    """Unlock evidence directory for new files."""
    case_dir = get_case_dir(getattr(args, "case", None))
    # TODO: implement remount read-write with interactive confirmation
    print(f"unlock-evidence for case at: {case_dir}")
    print("(not yet implemented)")


def cmd_register_evidence(args, identity: dict) -> None:
    """Register evidence file (hash + chmod 444)."""
    case_dir = get_case_dir(getattr(args, "case", None))
    # TODO: implement evidence registration
    print(f"register-evidence for case at: {case_dir}")
    print("(not yet implemented)")
