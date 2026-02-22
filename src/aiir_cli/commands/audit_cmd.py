"""Audit trail commands.

Read and summarize audit entries from the case directory:
  aiir audit log [--limit N] [--mcp <name>] [--tool <name>]
  aiir audit summary
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from aiir_cli.case_io import get_case_dir


def cmd_audit(args, identity: dict) -> None:
    """Handle audit subcommands."""
    action = getattr(args, "audit_action", None)
    if action == "log":
        _audit_log(args)
    elif action == "summary":
        _audit_summary(args)
    else:
        print("Usage: aiir audit {log|summary}", file=sys.stderr)
        sys.exit(1)


def _load_audit_entries(case_dir: Path) -> list[dict]:
    """Load all audit entries from audit/*.jsonl and approvals.jsonl."""
    entries: list[dict] = []
    corrupt_lines = 0

    audit_dir = case_dir / "audit"
    if audit_dir.is_dir():
        for jsonl_file in sorted(audit_dir.glob("*.jsonl")):
            try:
                file_text = jsonl_file.read_text()
            except OSError as e:
                print(f"  Warning: could not read {jsonl_file}: {e}", file=sys.stderr)
                continue
            for line in file_text.strip().split("\n"):
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    # Derive mcp name from filename if not present
                    if "mcp" not in entry:
                        entry["mcp"] = jsonl_file.stem
                    entries.append(entry)
                except json.JSONDecodeError:
                    corrupt_lines += 1

    approvals_file = case_dir / "approvals.jsonl"
    if approvals_file.exists():
        try:
            approvals_text = approvals_file.read_text()
        except OSError:
            approvals_text = ""
        for line in approvals_text.strip().split("\n"):
            if not line:
                continue
            try:
                entry = json.loads(line)
                entry.setdefault("tool", "approval")
                entry.setdefault("mcp", "aiir-cli")
                entries.append(entry)
            except json.JSONDecodeError:
                corrupt_lines += 1

    if corrupt_lines:
        print(f"  Warning: {corrupt_lines} corrupt JSONL line(s) skipped in audit trail", file=sys.stderr)

    entries.sort(key=lambda e: e.get("ts", ""))
    return entries


def _audit_log(args) -> None:
    """Show audit log entries with optional filters."""
    case_dir = get_case_dir(getattr(args, "case", None))
    entries = _load_audit_entries(case_dir)

    mcp_filter = getattr(args, "mcp", None)
    tool_filter = getattr(args, "tool", None)
    limit = getattr(args, "limit", 50) or 50
    if limit < 1:
        print("Error: --limit must be a positive integer.", file=sys.stderr)
        sys.exit(1)

    if mcp_filter:
        entries = [e for e in entries if e.get("mcp", "") == mcp_filter]
    if tool_filter:
        entries = [e for e in entries if e.get("tool", "") == tool_filter]

    entries = entries[-limit:]

    if not entries:
        print("No audit entries found.")
        return

    print(f"{'Timestamp':<22} {'Examiner':<12} {'MCP':<20} {'Tool':<25} Evidence ID")
    print("-" * 100)
    for e in entries:
        ts = e.get("ts", "?")[:19]
        examiner = e.get("examiner", "?")
        mcp = e.get("mcp", "?")
        tool = e.get("tool", "?")
        eid = e.get("evidence_id", "")
        print(f"{ts:<22} {examiner:<12} {mcp:<20} {tool:<25} {eid}")

    print(f"\nShowing {len(entries)} entries")


def _audit_summary(args) -> None:
    """Show audit summary: counts per MCP and per tool."""
    case_dir = get_case_dir(getattr(args, "case", None))
    entries = _load_audit_entries(case_dir)

    if not entries:
        print("No audit entries found.")
        return

    # Count by MCP
    mcp_counts: dict[str, int] = {}
    tool_counts: dict[str, dict[str, int]] = {}
    evidence_ids: set[str] = set()

    for e in entries:
        mcp = e.get("mcp", "unknown")
        tool = e.get("tool", "unknown")
        eid = e.get("evidence_id", "")

        mcp_counts[mcp] = mcp_counts.get(mcp, 0) + 1

        if mcp not in tool_counts:
            tool_counts[mcp] = {}
        tool_counts[mcp][tool] = tool_counts[mcp].get(tool, 0) + 1

        if eid:
            evidence_ids.add(eid)

    print("AUDIT SUMMARY")
    print("=" * 50)
    print(f"Total entries: {len(entries)}")
    print(f"Evidence IDs:  {len(evidence_ids)}")
    print()

    print("By MCP:")
    for mcp, count in sorted(mcp_counts.items()):
        print(f"  {mcp:<25} {count}")

    print()
    print("By Tool:")
    for mcp in sorted(tool_counts):
        for tool, count in sorted(tool_counts[mcp].items()):
            print(f"  {mcp:<20} {tool:<25} {count}")
