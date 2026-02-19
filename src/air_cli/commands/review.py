"""Review case status, audit trail, and evidence integrity."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

from air_cli.case_io import get_case_dir, load_findings, load_timeline


def cmd_review(args, identity: dict) -> None:
    """Review case information."""
    case_dir = get_case_dir(getattr(args, "case", None))

    if args.audit:
        _show_audit(case_dir, args.limit)
    elif args.evidence:
        _show_evidence(case_dir)
    elif args.findings:
        _show_findings(case_dir)
    else:
        _show_summary(case_dir)


def _show_summary(case_dir: Path) -> None:
    """Show case overview."""
    meta = _load_meta(case_dir)
    findings = load_findings(case_dir)
    timeline = load_timeline(case_dir)
    evidence = _load_evidence(case_dir)

    print(f"Case: {meta.get('case_id', '?')}")
    print(f"Name: {meta.get('name', '')}")
    print(f"Status: {meta.get('status', 'unknown')}")
    print(f"Created: {meta.get('created', '?')}")
    print()

    draft_f = sum(1 for f in findings if f.get("status") == "DRAFT")
    approved_f = sum(1 for f in findings if f.get("status") == "APPROVED")
    rejected_f = sum(1 for f in findings if f.get("status") == "REJECTED")
    print(f"Findings: {len(findings)} total ({draft_f} draft, {approved_f} approved, {rejected_f} rejected)")

    draft_t = sum(1 for t in timeline if t.get("status") == "DRAFT")
    approved_t = sum(1 for t in timeline if t.get("status") == "APPROVED")
    print(f"Timeline: {len(timeline)} events ({draft_t} draft, {approved_t} approved)")

    print(f"Evidence: {len(evidence)} registered files")


def _show_findings(case_dir: Path) -> None:
    """Show findings grouped by status."""
    findings = load_findings(case_dir)
    if not findings:
        print("No findings recorded.")
        return

    for status in ("DRAFT", "APPROVED", "REJECTED"):
        group = [f for f in findings if f.get("status") == status]
        if not group:
            continue
        print(f"\n{'=' * 60}")
        print(f"  {status} ({len(group)})")
        print(f"{'=' * 60}")
        for f in group:
            print(f"\n  [{f['id']}] {f.get('title', 'Untitled')}")
            print(f"    Confidence: {f.get('confidence', '?')}")
            print(f"    Evidence: {', '.join(f.get('evidence_ids', []))}")
            print(f"    Observation: {f.get('observation', '')[:120]}")
            if status == "APPROVED":
                print(f"    Approved: {f.get('approved_at', '?')}")
            elif status == "REJECTED":
                print(f"    Rejected: {f.get('rejected_at', '?')}")
                print(f"    Reason: {f.get('rejection_reason', '?')}")


def _show_evidence(case_dir: Path) -> None:
    """Show evidence registry and integrity status."""
    evidence = _load_evidence(case_dir)
    if not evidence:
        print("No evidence registered.")
        return

    print(f"{'=' * 60}")
    print(f"  Registered Evidence ({len(evidence)} files)")
    print(f"{'=' * 60}")

    for e in evidence:
        print(f"\n  {e.get('path', '?')}")
        print(f"    SHA256: {e.get('sha256', '?')}")
        print(f"    Description: {e.get('description', '')}")
        print(f"    Registered: {e.get('registered_at', '?')} by {e.get('registered_by', '?')}")

    # Show access log if exists
    access_log = case_dir / ".audit" / "evidence_access.jsonl"
    if access_log.exists():
        print(f"\n{'=' * 60}")
        print("  Evidence Access Log")
        print(f"{'=' * 60}")
        for line in access_log.read_text().strip().split("\n"):
            if not line:
                continue
            entry = json.loads(line)
            print(f"  {entry.get('ts', '?')} | {entry.get('action', '?')} | {entry.get('path', '?')} | {entry.get('user', '?')}")


def _show_audit(case_dir: Path, limit: int) -> None:
    """Show audit trail entries."""
    audit_dir = case_dir / ".audit"
    entries = []

    for jsonl_file in audit_dir.glob("*.jsonl"):
        if jsonl_file.name in ("evidence_access.jsonl", "approvals.jsonl"):
            continue
        for line in jsonl_file.read_text().strip().split("\n"):
            if not line:
                continue
            entries.append(json.loads(line))

    # Also include approvals
    approvals_file = audit_dir / "approvals.jsonl"
    if approvals_file.exists():
        for line in approvals_file.read_text().strip().split("\n"):
            if not line:
                continue
            entry = json.loads(line)
            entry["tool"] = "approval"
            entry["mcp"] = "air-cli"
            entries.append(entry)

    entries.sort(key=lambda e: e.get("ts", ""))
    entries = entries[-limit:]

    if not entries:
        print("No audit entries.")
        return

    print(f"{'=' * 60}")
    print(f"  Audit Trail (last {len(entries)} entries)")
    print(f"{'=' * 60}")

    for e in entries:
        ts = e.get("ts", "?")[:19]
        mcp = e.get("mcp", "?")
        tool = e.get("tool", "?")
        eid = e.get("evidence_id", "")
        print(f"  {ts} | {mcp:20s} | {tool:25s} | {eid}")


def _load_meta(case_dir: Path) -> dict:
    meta_file = case_dir / "CASE.yaml"
    if not meta_file.exists():
        return {}
    with open(meta_file) as f:
        return yaml.safe_load(f) or {}


def _load_evidence(case_dir: Path) -> list[dict]:
    reg_file = case_dir / ".audit" / "evidence.json"
    if not reg_file.exists():
        return []
    return json.loads(reg_file.read_text()).get("files", [])
