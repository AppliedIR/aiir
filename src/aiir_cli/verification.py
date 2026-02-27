"""HMAC verification ledger for approved findings and timeline events.

The verification ledger lives at /var/lib/aiir/verification/{case-id}.jsonl.
This path is outside any user's home directory and is unreachable by the
Claude Code sandbox from any CWD.

Each entry records an HMAC-SHA256 over the description text, keyed by
PBKDF2(PIN, salt). The LLM cannot forge entries because it does not know
the PIN-derived key.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
from pathlib import Path

VERIFICATION_DIR = Path("/var/lib/aiir/verification")
PBKDF2_ITERATIONS = 600_000


def _validate_case_id(case_id: str) -> None:
    """Validate case_id to prevent path traversal."""
    if not case_id:
        raise ValueError("Case ID cannot be empty")
    if ".." in case_id or "/" in case_id or "\\" in case_id:
        raise ValueError(f"Invalid case ID (path traversal characters): {case_id}")


def derive_hmac_key(pin: str, salt: bytes) -> bytes:
    """PBKDF2-derive HMAC key from PIN + salt."""
    return hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, PBKDF2_ITERATIONS)


def compute_hmac(derived_key: bytes, description: str) -> str:
    """HMAC-SHA256 over description text."""
    return hmac.new(
        derived_key, description.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def write_ledger_entry(case_id: str, entry: dict) -> None:
    """Append entry to /var/lib/aiir/verification/{case_id}.jsonl."""
    _validate_case_id(case_id)
    path = VERIFICATION_DIR / f"{case_id}.jsonl"
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")
        f.flush()
        os.fsync(f.fileno())
    os.chmod(path, 0o600)


def read_ledger(case_id: str) -> list[dict]:
    """Read all entries from verification ledger."""
    _validate_case_id(case_id)
    path = VERIFICATION_DIR / f"{case_id}.jsonl"
    if not path.exists():
        return []
    entries = []
    for line in path.read_text().splitlines():
        if line.strip():
            entries.append(json.loads(line))
    return entries


def copy_ledger_to_case(case_id: str, case_dir: Path) -> None:
    """Copy ledger to case dir for case close."""
    _validate_case_id(case_id)
    src = VERIFICATION_DIR / f"{case_id}.jsonl"
    if src.exists():
        shutil.copy2(src, case_dir / "verification.jsonl")


def verify_items(case_id: str, pin: str, salt: bytes, examiner: str) -> list[dict]:
    """Verify HMAC for all items belonging to examiner."""
    derived_key = derive_hmac_key(pin, salt)
    entries = read_ledger(case_id)
    results = []
    for entry in entries:
        if entry.get("approved_by") != examiner:
            continue
        expected = compute_hmac(derived_key, entry.get("description_snapshot", ""))
        actual = entry.get("hmac", "")
        results.append(
            {
                "finding_id": entry["finding_id"],
                "type": entry.get("type", "finding"),
                "verified": hmac.compare_digest(expected, actual),
            }
        )
    return results


def rehmac_entries(
    case_id: str,
    examiner: str,
    old_pin: str,
    old_salt: bytes,
    new_pin: str,
    new_salt: bytes,
) -> int:
    """Re-HMAC all entries for examiner after PIN rotation. Returns count."""
    _validate_case_id(case_id)
    path = VERIFICATION_DIR / f"{case_id}.jsonl"
    if not path.exists():
        return 0

    old_key = derive_hmac_key(old_pin, old_salt)
    new_key = derive_hmac_key(new_pin, new_salt)

    entries = read_ledger(case_id)
    count = 0
    updated = []
    for entry in entries:
        if entry.get("approved_by") != examiner:
            updated.append(entry)
            continue
        # Verify old HMAC first
        desc = entry.get("description_snapshot", "")
        expected = compute_hmac(old_key, desc)
        actual = entry.get("hmac", "")
        if not hmac.compare_digest(expected, actual):
            # HMAC doesn't match with old key — skip (don't corrupt)
            updated.append(entry)
            continue
        # Re-sign with new key
        entry["hmac"] = compute_hmac(new_key, desc)
        updated.append(entry)
        count += 1

    # Rewrite the file
    with open(path, "w") as f:
        for entry in updated:
            f.write(json.dumps(entry) + "\n")
        f.flush()
        os.fsync(f.fileno())
    os.chmod(path, 0o600)
    return count
