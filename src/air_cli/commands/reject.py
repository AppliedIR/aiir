"""Reject staged findings and timeline events."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from air_cli.case_io import load_findings, save_findings, load_timeline, save_timeline, get_case_dir, write_approval_log


def cmd_reject(args, identity: dict) -> None:
    """Reject findings/timeline events with required reason."""
    case_dir = get_case_dir(getattr(args, "case", None))
    findings = load_findings(case_dir)
    timeline = load_timeline(case_dir)
    rejected = []

    for item_id in args.ids:
        found = False
        for f in findings:
            if f["id"] == item_id and f["status"] == "DRAFT":
                f["status"] = "REJECTED"
                f["rejected_at"] = datetime.now(timezone.utc).isoformat()
                f["rejected_by"] = identity
                f["rejection_reason"] = args.reason
                write_approval_log(case_dir, item_id, "REJECTED", identity, reason=args.reason)
                rejected.append(item_id)
                found = True
                break
        if not found:
            for t in timeline:
                if t["id"] == item_id and t["status"] == "DRAFT":
                    t["status"] = "REJECTED"
                    t["rejected_at"] = datetime.now(timezone.utc).isoformat()
                    t["rejected_by"] = identity
                    t["rejection_reason"] = args.reason
                    write_approval_log(case_dir, item_id, "REJECTED", identity, reason=args.reason)
                    rejected.append(item_id)
                    found = True
                    break
        if not found:
            print(f"  {item_id}: not found or not DRAFT", file=sys.stderr)

    save_findings(case_dir, findings)
    save_timeline(case_dir, timeline)

    if rejected:
        print(f"Rejected: {', '.join(rejected)} — reason: {args.reason}")
