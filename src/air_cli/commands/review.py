"""Review case status, audit trail, and evidence integrity."""

from __future__ import annotations

from air_cli.case_io import get_case_dir


def cmd_review(args, identity: dict) -> None:
    """Review case information."""
    case_dir = get_case_dir(getattr(args, "case", None))
    # TODO: implement review subcommands (audit, evidence, findings)
    print(f"Review for case at: {case_dir}")
    print("(not yet implemented)")
