"""Shared case file I/O for CLI commands.

Multi-examiner aware: each examiner's data in examiners/{slug}/.
Read operations merge from all examiners/*/ for unified views.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import yaml


def _atomic_write(path: Path, content: str) -> None:
    """Write file atomically via temp file + rename to prevent data loss on crash."""
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def get_case_dir(case_id: str | None = None) -> Path:
    """Resolve the active case directory."""
    if case_id:
        cases_dir = Path(os.environ.get("AIIR_CASES_DIR", "cases"))
        case_dir = cases_dir / case_id
        if not case_dir.exists():
            print(f"Case not found: {case_id}", file=sys.stderr)
            sys.exit(1)
        return case_dir

    # Check AIIR_CASE_DIR env var
    env_dir = os.environ.get("AIIR_CASE_DIR")
    if env_dir:
        return Path(env_dir)

    # Check .aiir/active_case pointer
    active_file = Path(".aiir") / "active_case"
    if active_file.exists():
        case_id = active_file.read_text().strip()
        cases_dir = Path(os.environ.get("AIIR_CASES_DIR", "cases"))
        return cases_dir / case_id

    print("No active case. Use --case <id> or set AIIR_CASE_DIR.", file=sys.stderr)
    sys.exit(1)


def get_examiner(case_dir: Path | None = None) -> str:
    """Get the current examiner identity.

    Resolution: AIIR_EXAMINER > AIIR_ANALYST (deprecated) > CASE.yaml > OS user.
    """
    env_exam = os.environ.get("AIIR_EXAMINER", "").strip().lower()
    if env_exam:
        return env_exam
    env_analyst = os.environ.get("AIIR_ANALYST", "").strip().lower()
    if env_analyst:
        return env_analyst
    if case_dir:
        meta = load_case_meta(case_dir)
        exam = meta.get("examiner", "")
        if exam:
            return exam
    import getpass
    return getpass.getuser().lower()


def load_case_meta(case_dir: Path) -> dict:
    """Load CASE.yaml metadata."""
    meta_file = case_dir / "CASE.yaml"
    if not meta_file.exists():
        return {}
    with open(meta_file) as f:
        return yaml.safe_load(f) or {}


# --- Local store I/O (this examiner only) ---

def _examiner_dir(case_dir: Path) -> Path:
    """Return examiners/{slug}/ for the current examiner."""
    examiner = get_examiner(case_dir)
    return case_dir / "examiners" / examiner


def load_findings(case_dir: Path) -> list[dict]:
    """Load findings from examiners/{slug}/findings.json."""
    findings_file = _examiner_dir(case_dir) / "findings.json"
    if not findings_file.exists():
        return []
    return json.loads(findings_file.read_text())


def save_findings(case_dir: Path, findings: list[dict]) -> None:
    """Save findings to this examiner's store."""
    exam_dir = _examiner_dir(case_dir)
    exam_dir.mkdir(parents=True, exist_ok=True)
    _atomic_write(
        exam_dir / "findings.json",
        json.dumps(findings, indent=2, default=str),
    )


def load_timeline(case_dir: Path) -> list[dict]:
    """Load timeline events from examiners/{slug}/timeline.json."""
    timeline_file = _examiner_dir(case_dir) / "timeline.json"
    if not timeline_file.exists():
        return []
    return json.loads(timeline_file.read_text())


def save_timeline(case_dir: Path, timeline: list[dict]) -> None:
    """Save timeline to this examiner's store."""
    exam_dir = _examiner_dir(case_dir)
    exam_dir.mkdir(parents=True, exist_ok=True)
    _atomic_write(
        exam_dir / "timeline.json",
        json.dumps(timeline, indent=2, default=str),
    )


def load_todos(case_dir: Path) -> list[dict]:
    """Load TODO items from examiners/{slug}/todos.json."""
    todos_file = _examiner_dir(case_dir) / "todos.json"
    if not todos_file.exists():
        return []
    return json.loads(todos_file.read_text())


def save_todos(case_dir: Path, todos: list[dict]) -> None:
    """Save TODO items to this examiner's store."""
    exam_dir = _examiner_dir(case_dir)
    exam_dir.mkdir(parents=True, exist_ok=True)
    _atomic_write(
        exam_dir / "todos.json",
        json.dumps(todos, indent=2, default=str),
    )


# --- Merged reads (all examiners) ---

def load_all_findings(case_dir: Path) -> list[dict]:
    """Load findings from all examiners/*/, with scoped IDs."""
    findings = []
    examiners_root = case_dir / "examiners"
    if not examiners_root.is_dir():
        return findings
    for ex_dir in sorted(examiners_root.iterdir()):
        if not ex_dir.is_dir() or ex_dir.name.startswith("."):
            continue
        exam = ex_dir.name
        f_file = ex_dir / "findings.json"
        if f_file.exists():
            ex_findings = json.loads(f_file.read_text())
            for f in ex_findings:
                f.setdefault("examiner", exam)
                if "/" not in f.get("id", ""):
                    f["id"] = f"{exam}/{f['id']}"
            findings.extend(ex_findings)
    return findings


def load_all_timeline(case_dir: Path) -> list[dict]:
    """Load timeline from all examiners/*/, sorted chronologically."""
    timeline = []
    examiners_root = case_dir / "examiners"
    if not examiners_root.is_dir():
        return timeline
    for ex_dir in sorted(examiners_root.iterdir()):
        if not ex_dir.is_dir() or ex_dir.name.startswith("."):
            continue
        exam = ex_dir.name
        t_file = ex_dir / "timeline.json"
        if t_file.exists():
            ex_timeline = json.loads(t_file.read_text())
            for t in ex_timeline:
                t.setdefault("examiner", exam)
                if "/" not in t.get("id", ""):
                    t["id"] = f"{exam}/{t['id']}"
            timeline.extend(ex_timeline)
    timeline.sort(key=lambda t: t.get("timestamp", ""))
    return timeline


def load_all_todos(case_dir: Path) -> list[dict]:
    """Load TODOs from all examiners/*/."""
    todos = []
    examiners_root = case_dir / "examiners"
    if not examiners_root.is_dir():
        return todos
    for ex_dir in sorted(examiners_root.iterdir()):
        if not ex_dir.is_dir() or ex_dir.name.startswith("."):
            continue
        exam = ex_dir.name
        t_file = ex_dir / "todos.json"
        if t_file.exists():
            ex_todos = json.loads(t_file.read_text())
            for t in ex_todos:
                t.setdefault("examiner", exam)
                if "/" not in t.get("todo_id", ""):
                    t["todo_id"] = f"{exam}/{t['todo_id']}"
            todos.extend(ex_todos)
    return todos


def load_all_approvals(case_dir: Path) -> list[dict]:
    """Load approvals from all examiners/*/."""
    approvals = []
    examiners_root = case_dir / "examiners"
    if not examiners_root.is_dir():
        return approvals
    for ex_dir in sorted(examiners_root.iterdir()):
        if not ex_dir.is_dir() or ex_dir.name.startswith("."):
            continue
        approvals_file = ex_dir / "approvals.jsonl"
        if approvals_file.exists():
            for line in approvals_file.read_text().strip().split("\n"):
                if line:
                    approvals.append(json.loads(line))
    approvals.sort(key=lambda a: a.get("ts", ""))
    return approvals


# --- Approval I/O ---

def write_approval_log(
    case_dir: Path,
    item_id: str,
    action: str,
    identity: dict,
    reason: str = "",
    mode: str = "interactive",
) -> None:
    """Write approval/rejection record to examiners/{slug}/approvals.jsonl."""
    exam_dir = _examiner_dir(case_dir)
    exam_dir.mkdir(parents=True, exist_ok=True)
    log_file = exam_dir / "approvals.jsonl"
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "item_id": item_id,
        "action": action,
        "os_user": identity["os_user"],
        "examiner": identity.get("examiner", identity.get("analyst", "")),
        "examiner_source": identity.get("examiner_source", identity.get("analyst_source", "")),
        "mode": mode,
    }
    if reason:
        entry["reason"] = reason
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def load_approval_log(case_dir: Path) -> list[dict]:
    """Load approval records from examiners/{slug}/approvals.jsonl."""
    log_file = _examiner_dir(case_dir) / "approvals.jsonl"
    if not log_file.exists():
        return []
    entries = []
    for line in log_file.read_text().strip().split("\n"):
        if line:
            entries.append(json.loads(line))
    return entries


# --- Item lookup ---

def find_draft_item(item_id: str, findings: list[dict], timeline: list[dict]) -> dict | None:
    """Find a DRAFT item by ID in findings or timeline.

    Supports both scoped (jane/F-001) and unscoped (F-001) IDs.
    """
    for f in findings:
        fid = f["id"]
        # Match exact ID or match the local part (after /)
        if (fid == item_id or fid.endswith(f"/{item_id}")) and f["status"] == "DRAFT":
            return f
    for t in timeline:
        tid = t["id"]
        if (tid == item_id or tid.endswith(f"/{item_id}")) and t["status"] == "DRAFT":
            return t
    return None


# --- Integrity verification ---

def verify_approval_integrity(case_dir: Path) -> list[dict]:
    """Cross-reference findings against approvals.

    Returns findings with an added 'verification' field:
    - 'confirmed': status matches an approval record
    - 'no approval record': APPROVED/REJECTED but no matching record
    - 'draft': still in DRAFT status
    """
    findings = load_all_findings(case_dir)
    approvals = load_all_approvals(case_dir)

    # Build lookup: item_id -> last approval record
    last_approval = {}
    for record in approvals:
        last_approval[record["item_id"]] = record

    results = []
    for f in findings:
        result = dict(f)
        status = f.get("status", "DRAFT")
        fid = f["id"]
        # Match scoped (tester/F-001) or bare (F-001) IDs
        bare_id = fid.split("/")[-1] if "/" in fid else fid
        record = last_approval.get(fid) or last_approval.get(bare_id)
        if status == "DRAFT":
            result["verification"] = "draft"
        elif record:
            if record["action"] == status:
                result["verification"] = "confirmed"
            else:
                result["verification"] = "no approval record"
        else:
            result["verification"] = "no approval record"
        results.append(result)
    return results


# --- Sync bundle I/O ---

def export_bundle(case_dir: Path) -> dict:
    """Export this examiner's contributions as a bundle dict."""
    meta = load_case_meta(case_dir)
    examiner = get_examiner(case_dir)
    exam_dir = _examiner_dir(case_dir)

    bundle = {
        "schema_version": 1,
        "case_id": meta.get("case_id", ""),
        "examiner": examiner,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "since": None,
    }

    bundle["findings"] = load_findings(case_dir)
    for f in bundle["findings"]:
        f.setdefault("examiner", examiner)

    bundle["timeline"] = load_timeline(case_dir)
    for t in bundle["timeline"]:
        t.setdefault("examiner", examiner)

    bundle["todos"] = load_todos(case_dir)

    actions_jsonl = exam_dir / "actions.jsonl"
    bundle["actions_jsonl"] = actions_jsonl.read_text() if actions_jsonl.exists() else ""
    legacy_actions = exam_dir / "actions.md"
    bundle["actions_md"] = legacy_actions.read_text() if legacy_actions.exists() else ""

    bundle["approvals"] = load_approval_log(case_dir)

    # Audit entries
    audit: dict[str, list] = {}
    audit_dir = exam_dir / "audit"
    if audit_dir.is_dir():
        for jsonl_file in audit_dir.glob("*.jsonl"):
            mcp_name = jsonl_file.stem
            entries = []
            for line in jsonl_file.read_text().strip().split("\n"):
                if line:
                    entries.append(json.loads(line))
            audit[mcp_name] = entries
    bundle["audit"] = audit

    # Evidence manifest
    evidence_file = exam_dir / "evidence.json"
    manifest = []
    if evidence_file.exists():
        registry = json.loads(evidence_file.read_text())
        for entry in registry.get("files", []):
            manifest.append({
                "sha256": entry["sha256"],
                "description": entry.get("description", ""),
                "examiner": examiner,
            })
    bundle["evidence_manifest"] = manifest

    return bundle


def import_bundle(case_dir: Path, bundle: dict) -> dict:
    """Import a contribution bundle from another examiner into examiners/{examiner}/."""
    meta = load_case_meta(case_dir)
    bundle_examiner = bundle.get("examiner", "")

    if not bundle_examiner:
        return {"status": "error", "message": "Bundle missing examiner field"}
    if bundle_examiner == get_examiner(case_dir):
        return {"status": "error", "message": "Cannot import your own contributions"}
    if bundle.get("case_id") != meta.get("case_id"):
        return {"status": "error", "message": "Case ID mismatch"}

    import_dir = case_dir / "examiners" / bundle_examiner
    import_dir.mkdir(parents=True, exist_ok=True)
    (import_dir / "audit").mkdir(exist_ok=True)

    if "findings" in bundle:
        _atomic_write(import_dir / "findings.json", json.dumps(bundle["findings"], indent=2, default=str))
    if "timeline" in bundle:
        _atomic_write(import_dir / "timeline.json", json.dumps(bundle["timeline"], indent=2, default=str))
    if "todos" in bundle:
        _atomic_write(import_dir / "todos.json", json.dumps(bundle["todos"], indent=2, default=str))
    if bundle.get("actions_jsonl"):
        _atomic_write(import_dir / "actions.jsonl", bundle["actions_jsonl"])
    elif bundle.get("actions_md"):
        _atomic_write(import_dir / "actions.md", bundle["actions_md"])
    if "approvals" in bundle:
        with open(import_dir / "approvals.jsonl", "w") as f:
            for entry in bundle["approvals"]:
                f.write(json.dumps(entry, default=str) + "\n")
    if "audit" in bundle:
        for mcp_name, entries in bundle["audit"].items():
            with open(import_dir / "audit" / f"{mcp_name}.jsonl", "w") as f:
                for entry in entries:
                    f.write(json.dumps(entry, default=str) + "\n")
    if "evidence_manifest" in bundle:
        _atomic_write(import_dir / "evidence_manifest.json", json.dumps(bundle["evidence_manifest"], indent=2, default=str))

    # Update team list
    if bundle_examiner not in meta.get("team", []):
        meta.setdefault("team", []).append(bundle_examiner)
        _atomic_write(case_dir / "CASE.yaml", yaml.dump(meta, default_flow_style=False))

    return {
        "status": "imported",
        "examiner": bundle_examiner,
        "findings": len(bundle.get("findings", [])),
        "timeline": len(bundle.get("timeline", [])),
    }
