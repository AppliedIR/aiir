"""Approve staged findings and timeline events."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from air_cli.case_io import load_findings, save_findings, load_timeline, save_timeline, get_case_dir, write_approval_log


def cmd_approve(args, identity: dict) -> None:
    """Approve findings/timeline events."""
    case_dir = get_case_dir(getattr(args, "case", None))

    if args.all:
        _approve_all(case_dir, identity)
    elif args.review:
        _interactive_review(case_dir, identity)
    elif args.ids:
        _approve_specific(case_dir, args.ids, identity)
    else:
        print("Specify IDs to approve, --review, or --all", file=sys.stderr)
        sys.exit(1)


def _approve_specific(case_dir: Path, ids: list[str], identity: dict) -> None:
    """Approve specific finding/event IDs."""
    findings = load_findings(case_dir)
    timeline = load_timeline(case_dir)
    approved = []

    for item_id in ids:
        found = False
        for f in findings:
            if f["id"] == item_id and f["status"] == "DRAFT":
                f["status"] = "APPROVED"
                f["approved_at"] = datetime.now(timezone.utc).isoformat()
                f["approved_by"] = identity
                write_approval_log(case_dir, item_id, "APPROVED", identity)
                approved.append(item_id)
                found = True
                break
        if not found:
            for t in timeline:
                if t["id"] == item_id and t["status"] == "DRAFT":
                    t["status"] = "APPROVED"
                    t["approved_at"] = datetime.now(timezone.utc).isoformat()
                    t["approved_by"] = identity
                    write_approval_log(case_dir, item_id, "APPROVED", identity)
                    approved.append(item_id)
                    found = True
                    break
        if not found:
            print(f"  {item_id}: not found or not DRAFT", file=sys.stderr)

    save_findings(case_dir, findings)
    save_timeline(case_dir, timeline)

    if approved:
        print(f"Approved: {', '.join(approved)}")


def _approve_all(case_dir: Path, identity: dict) -> None:
    """Display all staged items, then prompt for batch approval."""
    findings = load_findings(case_dir)
    timeline = load_timeline(case_dir)

    drafts = [f for f in findings if f["status"] == "DRAFT"]
    draft_events = [t for t in timeline if t["status"] == "DRAFT"]

    if not drafts and not draft_events:
        print("No staged items to approve.")
        return

    # Display all items — human MUST see them
    print("=" * 70)
    print("STAGED ITEMS FOR APPROVAL")
    print("=" * 70)

    for f in drafts:
        print(f"\n[{f['id']}] {f.get('title', 'Untitled')}")
        print(f"  Confidence: {f.get('confidence', '?')}")
        print(f"  Evidence: {', '.join(f.get('evidence_ids', []))}")
        print(f"  Observation: {f.get('observation', '')[:120]}")

    for t in draft_events:
        print(f"\n[{t['id']}] {t.get('timestamp', '?')} — {t.get('description', '')[:120]}")

    total = len(drafts) + len(draft_events)
    print(f"\n{'=' * 70}")

    # Interactive confirmation
    response = input(f"Approve all {total} item(s)? [y/N]: ").strip().lower()
    if response != "y":
        print("Cancelled.")
        return

    # Approve all
    for f in drafts:
        f["status"] = "APPROVED"
        f["approved_at"] = datetime.now(timezone.utc).isoformat()
        f["approved_by"] = identity
        write_approval_log(case_dir, f["id"], "APPROVED", identity)

    for t in draft_events:
        t["status"] = "APPROVED"
        t["approved_at"] = datetime.now(timezone.utc).isoformat()
        t["approved_by"] = identity
        write_approval_log(case_dir, t["id"], "APPROVED", identity)

    save_findings(case_dir, findings)
    save_timeline(case_dir, timeline)
    print(f"Approved {total} item(s).")


def _interactive_review(case_dir: Path, identity: dict) -> None:
    """Review each staged item one by one: Y/N/skip."""
    findings = load_findings(case_dir)
    timeline = load_timeline(case_dir)

    all_items = [(f, "finding", findings) for f in findings if f["status"] == "DRAFT"]
    all_items += [(t, "timeline", timeline) for t in timeline if t["status"] == "DRAFT"]

    if not all_items:
        print("No staged items to review.")
        return

    approved_count = 0
    for item, item_type, collection in all_items:
        print(f"\n{'=' * 70}")
        print(f"[{item['id']}] ({item_type})")
        if item_type == "finding":
            print(f"  Title: {item.get('title', 'Untitled')}")
            print(f"  Confidence: {item.get('confidence', '?')}")
            print(f"  Evidence: {', '.join(item.get('evidence_ids', []))}")
            print(f"  Observation: {item.get('observation', '')}")
            print(f"  Interpretation: {item.get('interpretation', '')}")
        else:
            print(f"  Timestamp: {item.get('timestamp', '?')}")
            print(f"  Description: {item.get('description', '')}")

        response = input("  Approve? [Y/n/q]: ").strip().lower()
        if response == "q":
            break
        if response in ("", "y"):
            item["status"] = "APPROVED"
            item["approved_at"] = datetime.now(timezone.utc).isoformat()
            item["approved_by"] = identity
            write_approval_log(case_dir, item["id"], "APPROVED", identity)
            approved_count += 1
            print(f"  -> APPROVED")
        else:
            print(f"  -> skipped")

    save_findings(case_dir, findings)
    save_timeline(case_dir, timeline)
    print(f"\n{approved_count} item(s) approved.")
