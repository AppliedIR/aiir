"""Approve staged findings and timeline events.

Every approval requires human confirmation via /dev/tty (or PIN).
This blocks AI-via-Bash from approving without human involvement.
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


def cmd_approve(args, identity: dict) -> None:
    """Approve findings/timeline events."""
    case_dir = get_case_dir(getattr(args, "case", None))
    config_path = Path.home() / ".air" / "config.yaml"

    if args.ids:
        _approve_specific(case_dir, args.ids, identity, config_path)
    else:
        _interactive_review(case_dir, identity, config_path)


def _approve_specific(case_dir: Path, ids: list[str], identity: dict, config_path: Path) -> None:
    """Approve specific finding/event IDs after displaying them."""
    findings = load_findings(case_dir)
    timeline = load_timeline(case_dir)
    to_approve = []

    for item_id in ids:
        item = _find_draft_item(item_id, findings, timeline)
        if item is None:
            print(f"  {item_id}: not found or not DRAFT", file=sys.stderr)
            continue
        _display_item(item)
        to_approve.append(item)

    if not to_approve:
        print("No items to approve.")
        return

    print(f"\n{len(to_approve)} item(s) to approve.")
    mode = require_confirmation(config_path, identity["analyst"])

    now = datetime.now(timezone.utc).isoformat()
    for item in to_approve:
        item["status"] = "APPROVED"
        item["approved_at"] = now
        item["approved_by"] = identity
        write_approval_log(case_dir, item["id"], "APPROVED", identity, mode=mode)

    save_findings(case_dir, findings)
    save_timeline(case_dir, timeline)
    approved_ids = [item["id"] for item in to_approve]
    print(f"Approved: {', '.join(approved_ids)}")


def _interactive_review(case_dir: Path, identity: dict, config_path: Path) -> None:
    """Review each DRAFT item one by one: [Enter]=approve, [r]eject, [d]raft (skip)."""
    findings = load_findings(case_dir)
    timeline = load_timeline(case_dir)

    drafts = [f for f in findings if f["status"] == "DRAFT"]
    draft_events = [t for t in timeline if t["status"] == "DRAFT"]
    all_items = drafts + draft_events

    if not all_items:
        print("No staged items to review.")
        return

    dispositions = {}  # item_id -> "approve" | "reject" | "draft"

    for item in all_items:
        _display_item(item)
        while True:
            try:
                response = input("  [Enter]=approve  [r]eject  [d]raft(skip): ").strip().lower()
            except EOFError:
                response = "d"
            if response in ("", "a"):
                dispositions[item["id"]] = "approve"
                print(f"  -> tagged APPROVE")
                break
            elif response == "r":
                reason = input("  Rejection reason (optional): ").strip()
                dispositions[item["id"]] = ("reject", reason)
                print(f"  -> tagged REJECT")
                break
            elif response == "d":
                dispositions[item["id"]] = "draft"
                print(f"  -> skipped (remains DRAFT)")
                break
            else:
                print("  Invalid choice. Enter, r, or d.")

    approvals = {k: v for k, v in dispositions.items() if v == "approve"}
    rejections = {k: v for k, v in dispositions.items() if isinstance(v, tuple)}
    skipped = {k: v for k, v in dispositions.items() if v == "draft"}

    # Summary
    print(f"\n{'=' * 60}")
    print(f"  Summary: {len(approvals)} approve, {len(rejections)} reject, {len(skipped)} skip")
    print(f"{'=' * 60}")

    if not approvals and not rejections:
        print("Nothing to commit.")
        return

    mode = require_confirmation(config_path, identity["analyst"])

    now = datetime.now(timezone.utc).isoformat()

    # Apply approvals
    for item in all_items:
        if item["id"] in approvals:
            item["status"] = "APPROVED"
            item["approved_at"] = now
            item["approved_by"] = identity
            write_approval_log(case_dir, item["id"], "APPROVED", identity, mode=mode)

    # Apply rejections
    for item in all_items:
        disp = dispositions.get(item["id"])
        if isinstance(disp, tuple):
            _, reason = disp
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
    print(f"Committed {len(approvals) + len(rejections)} disposition(s).")


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
    print(f"\n{'=' * 60}")
    print(f"  [{item['id']}]  {item.get('title', item.get('description', 'Untitled'))}")
    print(f"{'=' * 60}")
    if "title" in item:
        # It's a finding
        print(f"  Confidence: {item.get('confidence', '?')}")
        print(f"  Evidence: {', '.join(item.get('evidence_ids', []))}")
        print(f"  Observation: {item.get('observation', '')}")
        print(f"  Interpretation: {item.get('interpretation', '')}")
        if item.get("iocs"):
            print(f"  IOCs: {item['iocs']}")
    else:
        # It's a timeline event
        print(f"  Timestamp: {item.get('timestamp', '?')}")
        print(f"  Description: {item.get('description', '')}")
        if item.get("evidence_ids"):
            print(f"  Evidence: {', '.join(item['evidence_ids'])}")
