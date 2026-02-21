"""Approve staged findings and timeline events.

Every approval requires human confirmation via /dev/tty (or PIN).
This blocks AI-via-Bash from approving without human involvement.

Interactive review options per item:
  [a]pprove  — approve as-is
  [e]dit     — open in $EDITOR as YAML, approve with modifications tracked
  [n]ote     — add examiner note, then approve
  [r]eject   — reject with optional reason
  [t]odo     — create TODO and skip the item
  [s]kip     — leave as DRAFT
  [q]uit     — stop reviewing, commit what's been decided so far
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import yaml

from aiir_cli.approval_auth import require_confirmation
from aiir_cli.case_io import (
    compute_content_hash,
    find_draft_item,
    get_case_dir,
    load_findings,
    load_timeline,
    load_all_findings,
    load_all_timeline,
    load_todos,
    save_findings,
    save_timeline,
    save_todos,
    write_approval_log,
)


def cmd_approve(args, identity: dict) -> None:
    """Approve findings/timeline events."""
    case_dir = get_case_dir(getattr(args, "case", None))
    config_path = Path.home() / ".aiir" / "config.yaml"

    if args.ids:
        # Specific-ID mode with optional flags
        note = getattr(args, "note", None)
        edit = getattr(args, "edit", False)
        interpretation = getattr(args, "interpretation", None)
        _approve_specific(case_dir, args.ids, identity, config_path,
                          note=note, edit=edit, interpretation=interpretation)
    else:
        # Interactive review mode
        by_filter = getattr(args, "by", None)
        findings_only = getattr(args, "findings_only", False)
        timeline_only = getattr(args, "timeline_only", False)
        _interactive_review(case_dir, identity, config_path,
                            by_filter=by_filter, findings_only=findings_only,
                            timeline_only=timeline_only)


def _approve_specific(
    case_dir: Path,
    ids: list[str],
    identity: dict,
    config_path: Path,
    note: str | None = None,
    edit: bool = False,
    interpretation: str | None = None,
) -> None:
    """Approve specific finding/event IDs with optional modifications."""
    findings = load_all_findings(case_dir)
    timeline = load_all_timeline(case_dir)
    to_approve = []

    for item_id in ids:
        item = find_draft_item(item_id, findings, timeline)
        if item is None:
            print(f"  {item_id}: not found or not DRAFT", file=sys.stderr)
            continue
        _display_item(item)
        to_approve.append(item)

    if not to_approve:
        print("No items to approve.")
        return

    # Apply modifications before confirmation
    for item in to_approve:
        if edit:
            _apply_edit(item, identity)
        if interpretation:
            _apply_field_override(item, "interpretation", interpretation, identity)
        if note:
            _apply_note(item, note, identity)

    print(f"\n{len(to_approve)} item(s) to approve.")
    mode = require_confirmation(config_path, identity["examiner"])

    now = datetime.now(timezone.utc).isoformat()
    for item in to_approve:
        item["content_hash"] = compute_content_hash(item)
        item["status"] = "APPROVED"
        item["approved_at"] = now
        item["approved_by"] = identity["examiner"]
        write_approval_log(case_dir, item["id"], "APPROVED", identity, mode=mode)

    # Save back to local store (approvals apply to local data)
    # For cross-examiner items, the approval record in approvals.jsonl tracks it
    local_findings = load_findings(case_dir)
    local_timeline = load_timeline(case_dir)
    # Update any local items that were approved
    _SYNC_KEYS = (
        "status", "approved_at", "approved_by", "content_hash",
        "examiner_notes", "examiner_modifications",
        "interpretation", "title", "confidence", "confidence_justification",
        "observation", "description", "source", "timestamp",
    )
    local_ids = {f["id"] for f in local_findings} | {t["id"] for t in local_timeline}
    for item in to_approve:
        # Strip examiner prefix to match local ID
        bare_id = item["id"].split("/")[-1] if "/" in item["id"] else item["id"]
        if bare_id in local_ids or item["id"] in local_ids:
            for f in local_findings:
                if f["id"] == bare_id:
                    f.update({k: item[k] for k in _SYNC_KEYS if k in item})
            for t in local_timeline:
                if t["id"] == bare_id:
                    t.update({k: item[k] for k in _SYNC_KEYS if k in item})
    save_findings(case_dir, local_findings)
    save_timeline(case_dir, local_timeline)
    approved_ids = [item["id"] for item in to_approve]
    print(f"Approved: {', '.join(approved_ids)}")


def _interactive_review(
    case_dir: Path,
    identity: dict,
    config_path: Path,
    by_filter: str | None = None,
    findings_only: bool = False,
    timeline_only: bool = False,
) -> None:
    """Review each DRAFT item with full per-item options."""
    findings = load_all_findings(case_dir)
    timeline = load_all_timeline(case_dir)

    drafts = [] if timeline_only else [f for f in findings if f.get("status") == "DRAFT"]
    draft_events = [] if findings_only else [t for t in timeline if t.get("status") == "DRAFT"]
    all_items = drafts + draft_events

    # Filter by creator
    if by_filter:
        all_items = [i for i in all_items if i.get("created_by") == by_filter]

    if not all_items:
        print("No staged items to review.")
        return

    print(f"Reviewing {len(all_items)} DRAFT item(s)...\n")

    # Collect dispositions
    dispositions: dict[str, tuple] = {}  # id -> (action, extra_data)
    todos_to_create: list[dict] = []

    for item in all_items:
        _display_item(item)
        choice = _prompt_choice()

        if choice == "approve":
            dispositions[item["id"]] = ("approve", None)
            print(f"  -> APPROVE")

        elif choice == "edit":
            _apply_edit(item, identity)
            dispositions[item["id"]] = ("approve", "edited")
            print(f"  -> APPROVE (with edits)")

        elif choice == "note":
            try:
                note_text = input("  Note: ").strip()
            except EOFError:
                note_text = ""
            if note_text:
                _apply_note(item, note_text, identity)
            dispositions[item["id"]] = ("approve", "noted")
            print(f"  -> APPROVE (with note)")

        elif choice == "reject":
            try:
                reason = input("  Rejection reason (optional): ").strip()
            except EOFError:
                reason = ""
            dispositions[item["id"]] = ("reject", reason)
            print(f"  -> REJECT")

        elif choice == "todo":
            try:
                desc = input("  TODO description: ").strip()
                assignee = input("  Assign to [unassigned]: ").strip()
                priority = input("  Priority [medium]: ").strip() or "medium"
            except EOFError:
                desc = "Follow up on " + item["id"]
                assignee = ""
                priority = "medium"
            if desc:
                todos_to_create.append({
                    "description": desc,
                    "assignee": assignee,
                    "priority": priority,
                    "related_findings": [item["id"]],
                })
            dispositions[item["id"]] = ("skip", None)
            print(f"  -> skip (TODO created)")

        elif choice == "skip":
            dispositions[item["id"]] = ("skip", None)
            print(f"  -> skip (remains DRAFT)")

        elif choice == "quit":
            print("  Stopping review.")
            break

    # Summary
    approvals = {k for k, v in dispositions.items() if v[0] == "approve"}
    rejections = {k for k, v in dispositions.items() if v[0] == "reject"}
    skipped = {k for k, v in dispositions.items() if v[0] == "skip"}

    print(f"\n{'=' * 60}")
    print(f"  Summary: {len(approvals)} approve, {len(rejections)} reject, "
          f"{len(skipped)} skip, {len(todos_to_create)} TODO(s) created")
    print(f"{'=' * 60}")

    if not approvals and not rejections:
        # Still create TODOs even if nothing to commit
        if todos_to_create:
            _create_todos(case_dir, todos_to_create, identity)
        print("Nothing to commit.")
        return

    mode = require_confirmation(config_path, identity["examiner"])

    now = datetime.now(timezone.utc).isoformat()

    # Apply approvals
    for item in all_items:
        if item["id"] in approvals:
            item["content_hash"] = compute_content_hash(item)
            item["status"] = "APPROVED"
            item["approved_at"] = now
            item["approved_by"] = identity["examiner"]
            write_approval_log(case_dir, item["id"], "APPROVED", identity, mode=mode)

    # Apply rejections
    for item in all_items:
        disp = dispositions.get(item["id"])
        if disp and disp[0] == "reject":
            reason = disp[1] or ""
            item["status"] = "REJECTED"
            item["rejected_at"] = now
            item["rejected_by"] = identity["examiner"]
            if reason:
                item["rejection_reason"] = reason
            write_approval_log(
                case_dir, item["id"], "REJECTED", identity, reason=reason, mode=mode
            )

    # Save back to local store — update local items that were changed
    local_findings = load_findings(case_dir)
    local_timeline = load_timeline(case_dir)
    _SYNC_KEYS_INTERACTIVE = (
        "status", "approved_at", "approved_by", "content_hash",
        "rejected_at", "rejected_by", "rejection_reason",
        "examiner_notes", "examiner_modifications",
        "interpretation", "title", "confidence", "confidence_justification",
        "observation", "description", "source", "timestamp",
    )
    changed_items = {item["id"]: item for item in all_items if item["id"] in approvals | rejections}
    for item_id, item in changed_items.items():
        bare_id = item_id.split("/")[-1] if "/" in item_id else item_id
        for f in local_findings:
            if f["id"] == bare_id:
                f.update({k: item[k] for k in _SYNC_KEYS_INTERACTIVE if k in item})
        for t in local_timeline:
            if t["id"] == bare_id:
                t.update({k: item[k] for k in _SYNC_KEYS_INTERACTIVE if k in item})
    save_findings(case_dir, local_findings)
    save_timeline(case_dir, local_timeline)

    # Create TODOs
    if todos_to_create:
        _create_todos(case_dir, todos_to_create, identity)

    print(f"Committed {len(approvals) + len(rejections)} disposition(s).")


def _prompt_choice() -> str:
    """Prompt for per-item action."""
    while True:
        try:
            response = input(
                "  [a]pprove  [e]dit  [n]ote  [r]eject  [t]odo  [s]kip  [q]uit: "
            ).strip().lower()
        except EOFError:
            return "skip"
        if response in ("", "a"):
            return "approve"
        if response == "e":
            return "edit"
        if response == "n":
            return "note"
        if response == "r":
            return "reject"
        if response == "t":
            return "todo"
        if response == "s":
            return "skip"
        if response == "q":
            return "quit"
        print("  Invalid choice.")


def _apply_edit(item: dict, identity: dict) -> None:
    """Open item in $EDITOR as YAML, track modifications."""
    editor = os.environ.get("EDITOR", "vi")

    # Serialize editable fields
    editable = {}
    if "title" in item:
        # Finding
        for key in ("title", "observation", "interpretation", "confidence",
                     "confidence_justification", "type"):
            if key in item:
                editable[key] = item[key]
    else:
        # Timeline event
        for key in ("timestamp", "description", "source"):
            if key in item:
                editable[key] = item[key]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(editable, f, default_flow_style=False, allow_unicode=True)
        tmpfile = f.name

    try:
        subprocess.run([editor, tmpfile], check=True, timeout=3600)
    except subprocess.TimeoutExpired:
        print("  Editor timed out after 1 hour.", file=sys.stderr)
        try:
            os.unlink(tmpfile)
        except OSError:
            pass
        return
    except subprocess.CalledProcessError as e:
        print(f"  Editor exited with error: {e}", file=sys.stderr)
        try:
            os.unlink(tmpfile)
        except OSError:
            pass
        return
    except OSError as e:
        print(f"  Failed to launch editor '{editor}': {e}", file=sys.stderr)
        try:
            os.unlink(tmpfile)
        except OSError:
            pass
        return

    try:
        with open(tmpfile) as f:
            edited = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        print(f"  Edited file contains invalid YAML: {e}", file=sys.stderr)
        try:
            os.unlink(tmpfile)
        except OSError:
            pass
        return
    except OSError as e:
        print(f"  Failed to read edited file: {e}", file=sys.stderr)
        try:
            os.unlink(tmpfile)
        except OSError:
            pass
        return
    finally:
        try:
            os.unlink(tmpfile)
        except OSError:
            pass

    # Diff and record modifications
    modifications = {}
    now = datetime.now(timezone.utc).isoformat()
    for key, new_val in edited.items():
        old_val = editable.get(key)
        if new_val != old_val:
            modifications[key] = {
                "original": old_val,
                "modified": new_val,
                "modified_by": identity["examiner"],
                "modified_at": now,
            }
            item[key] = new_val

    if modifications:
        item.setdefault("examiner_modifications", {}).update(modifications)


def _apply_field_override(item: dict, field: str, value: str, identity: dict) -> None:
    """Override a specific field and track the modification."""
    original = item.get(field)
    if original == value:
        return
    now = datetime.now(timezone.utc).isoformat()
    item[field] = value
    item.setdefault("examiner_modifications", {})[field] = {
        "original": original,
        "modified": value,
        "modified_by": identity["examiner"],
        "modified_at": now,
    }


def _apply_note(item: dict, note: str, identity: dict) -> None:
    """Add an examiner note to the item."""
    now = datetime.now(timezone.utc).isoformat()
    item.setdefault("examiner_notes", []).append({
        "note": note,
        "by": identity["examiner"],
        "at": now,
    })


def _create_todos(case_dir: Path, todos_to_create: list[dict], identity: dict) -> None:
    """Create TODO items in the case."""
    todos = load_todos(case_dir)
    for td in todos_to_create:
        todo_id = f"TODO-{len(todos) + 1:03d}"
        todo = {
            "todo_id": todo_id,
            "description": td["description"],
            "status": "open",
            "priority": td.get("priority", "medium"),
            "assignee": td.get("assignee", ""),
            "related_findings": td.get("related_findings", []),
            "created_by": identity["examiner"],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "notes": [],
            "completed_at": None,
        }
        todos.append(todo)
        print(f"  Created {todo_id}: {td['description']}")
    save_todos(case_dir, todos)


def _display_item(item: dict) -> None:
    """Display a finding or timeline event."""
    status = item.get("status", "?")
    created_by = item.get("created_by", "")
    examiner = item.get("examiner", "")
    print(f"\n{'─' * 60}")
    print(f"  [{item['id']}]  {item.get('title', item.get('description', 'Untitled'))}")
    if examiner:
        print(f"  Examiner: {examiner}", end="")
    if created_by:
        print(f"  | By: {created_by}", end="")
    if item.get("confidence"):
        print(f"  | Confidence: {item['confidence']}", end="")
    if item.get("evidence_ids"):
        print(f"  | Evidence: {', '.join(item['evidence_ids'])}", end="")
    print()
    print(f"{'─' * 60}")

    if "title" in item:
        # It's a finding
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
    print()
