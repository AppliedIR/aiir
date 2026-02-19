"""Execute forensic commands with case context and audit trail."""

from __future__ import annotations

import sys

from air_cli.case_io import get_case_dir


def cmd_exec(args, identity: dict) -> None:
    """Execute a forensic command with audit logging."""
    case_dir = get_case_dir(getattr(args, "case", None))
    # TODO: implement exec with audit trail
    print(f"exec for case at: {case_dir}")
    print("(not yet implemented)")
