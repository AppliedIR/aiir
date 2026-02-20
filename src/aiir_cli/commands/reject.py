"""Reject staged findings and timeline events.

Every rejection requires human confirmation via /dev/tty (or PIN).
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from aiir_cli.approval_auth import require_confirmation
from aiir_cli.case_io import (
    find_draft_item,
    get_case_dir,
    load_findings,
    load_timeline,
    save_findings,
    save_timeline,
    write_approval_log,
)


def cmd_reject(args, identity: dict) -> None:
    """Reject specific findings/timeline events."""
    case_dir = get_case_dir(getattr(args, "case", None))
    config_path = Path.home() / ".aiir" / "config.yaml"
    findings = load_findings(case_dir)
    timeline = load_timeline(case_dir)
    to_reject = []

    for item_id in args.ids:
        item = find_draft_item(item_id, findings, timeline)
        if item is None:
            print(f"  {item_id}: not found or not DRAFT", file=sys.stderr)
            continue
        _display_item(item)
        to_reject.append(item)

    if not to_reject:
        print("No items to reject.")
        return

    reason = getattr(args, "reason", "") or ""
    print(f"\n{len(to_reject)} item(s) to reject.")
    if reason:
        print(f"  Reason: {reason}")

    mode = require_confirmation(config_path, identity["examiner"])

    # Reload from disk to preserve any concurrent MCP writes
    reject_ids = [item["id"] for item in to_reject]
    findings = load_findings(case_dir)
    timeline = load_timeline(case_dir)

    now = datetime.now(timezone.utc).isoformat()
    rejected = []
    for item_id in reject_ids:
        item = find_draft_item(item_id, findings, timeline)
        if item is None:
            continue
        item["status"] = "REJECTED"
        item["rejected_at"] = now
        item["rejected_by"] = identity["examiner"]
        if reason:
            item["rejection_reason"] = reason
        write_approval_log(
            case_dir, item_id, "REJECTED", identity, reason=reason, mode=mode
        )
        rejected.append(item_id)

    save_findings(case_dir, findings)
    save_timeline(case_dir, timeline)

    msg = f"Rejected: {', '.join(rejected)}"
    if reason:
        msg += f" — reason: {reason}"
    print(msg)


def _display_item(item: dict) -> None:
    """Display a finding or timeline event with full context for rejection decisions."""
    print(f"\n{'─' * 60}")
    print(f"  [{item['id']}]  {item.get('title', item.get('description', 'Untitled'))}")
    if item.get("confidence"):
        print(f"  Confidence: {item['confidence']}", end="")
    if item.get("evidence_ids"):
        print(f"  | Evidence: {', '.join(item['evidence_ids'])}", end="")
    print()
    print(f"{'─' * 60}")

    if "title" in item:
        print(f"  Observation: {item.get('observation', '')}")
        print(f"  Interpretation: {item.get('interpretation', '')}")
    else:
        print(f"  Timestamp: {item.get('timestamp', '?')}")
        print(f"  Description: {item.get('description', '')}")
    print()
