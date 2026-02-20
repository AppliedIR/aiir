"""Sync commands for multi-examiner collaboration.

Export/import contribution bundles between examiners.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from aiir_cli.case_io import (
    export_bundle,
    get_case_dir,
    import_bundle,
)


def cmd_sync(args, identity: dict) -> None:
    """Dispatch sync subcommands."""
    action = getattr(args, "sync_action", None)
    if action == "export":
        _sync_export(args, identity)
    elif action == "import":
        _sync_import(args, identity)
    else:
        print("Usage: aiir sync {export|import}", file=sys.stderr)
        print("  aiir sync export --file jane-bundle.json")
        print("  aiir sync import --file jane-bundle.json")
        sys.exit(1)


def _sync_export(args, identity: dict) -> None:
    """Export this examiner's contributions to a bundle file."""
    case_dir = get_case_dir(getattr(args, "case", None))
    output_file = Path(getattr(args, "file", ""))

    if not output_file.name:
        print("--file is required for sync export", file=sys.stderr)
        sys.exit(1)

    bundle = export_bundle(case_dir)

    with open(output_file, "w") as f:
        json.dump(bundle, f, indent=2, default=str)

    print(f"Exported bundle to {output_file}")
    print(f"  Examiner: {bundle.get('examiner', '?')}")
    print(f"  Findings: {len(bundle.get('findings', []))}")
    print(f"  Timeline: {len(bundle.get('timeline', []))}")
    print(f"  TODOs: {len(bundle.get('todos', []))}")
    print(f"  Approvals: {len(bundle.get('approvals', []))}")
    audit_count = sum(len(v) for v in bundle.get("audit", {}).values())
    print(f"  Audit entries: {audit_count}")


def _sync_import(args, identity: dict) -> None:
    """Import a contribution bundle from another examiner."""
    case_dir = get_case_dir(getattr(args, "case", None))
    input_file = Path(getattr(args, "file", ""))

    if not input_file.name:
        print("--file is required for sync import", file=sys.stderr)
        sys.exit(1)

    if not input_file.exists():
        print(f"File not found: {input_file}", file=sys.stderr)
        sys.exit(1)

    with open(input_file) as f:
        bundle = json.load(f)

    result = import_bundle(case_dir, bundle)

    if result.get("status") == "error":
        print(f"Import failed: {result.get('message')}", file=sys.stderr)
        sys.exit(1)

    print(f"Imported contributions from {result.get('examiner', '?')}")
    print(f"  Findings: {result.get('findings', 0)}")
    print(f"  Timeline: {result.get('timeline', 0)}")
