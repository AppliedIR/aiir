"""Reject staged findings and timeline events.

Every rejection requires human confirmation via /dev/tty (or PIN).
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from air_cli.approval_auth import require_confirmation
from air_cli.case_io import (
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
    config_path = Path.home() / ".air" / "config.yaml"
    findings = load_findings(case_dir)
    timeline = load_timeline(case_dir)
    to_reject = []

    for item_id in args.ids:
        item = _find_draft_item(item_id, findings, timeline)
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

    mode = require_confirmation(config_path, identity["analyst"])

    now = datetime.now(timezone.utc).isoformat()
    for item in to_reject:
        item["status"] = "REJECTED"
        item["rejected_at"] = now
        item["rejected_by"] = identity
        if reason:
            item["rejection_reason"] = reason
        write_approval_log(
            case_dir, item["id"], "REJECTED", identity, reason=reason, mode=mode
        )

    save_findings(case_dir, findings)
    save_timeline(case_dir, timeline)

    rejected_ids = [item["id"] for item in to_reject]
    msg = f"Rejected: {', '.join(rejected_ids)}"
    if reason:
        msg += f" — reason: {reason}"
    print(msg)


def _find_draft_item(item_id: str, findings: list[dict], timeline: list[dict]) -> dict | None:
    """Find a DRAFT item by ID in findings or timeline."""
    for f in findings:
        if f["id"] == item_id and f["status"] == "DRAFT":
            return f
    for t in timeline:
        if t["id"] == item_id and t["status"] == "DRAFT":
            return t
    return None


def _display_item(item: dict) -> None:
    """Display a finding or timeline event."""
    print(f"\n  [{item['id']}]  {item.get('title', item.get('description', 'Untitled'))}")
    if "title" in item:
        print(f"  Confidence: {item.get('confidence', '?')}")
        print(f"  Observation: {item.get('observation', '')[:120]}")
    else:
        print(f"  Timestamp: {item.get('timestamp', '?')}")
        print(f"  Description: {item.get('description', '')[:120]}")
