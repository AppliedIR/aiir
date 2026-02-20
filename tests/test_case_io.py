"""Tests for shared case I/O module."""

import json
import os
from pathlib import Path

import pytest

from aiir_cli.case_io import (
    get_case_dir,
    load_findings,
    save_findings,
    load_timeline,
    save_timeline,
    write_approval_log,
    regenerate_findings_md,
    regenerate_timeline_md,
)


@pytest.fixture
def case_dir(tmp_path):
    """Create a minimal case directory."""
    audit_dir = tmp_path / ".audit"
    audit_dir.mkdir()
    return tmp_path


class TestGetCaseDir:
    def test_from_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
        assert get_case_dir() == tmp_path

    def test_from_explicit_id(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path))
        case = tmp_path / "INC-TEST"
        case.mkdir()
        result = get_case_dir("INC-TEST")
        assert result == case

    def test_no_case_exits(self, monkeypatch):
        monkeypatch.delenv("AIIR_CASE_DIR", raising=False)
        monkeypatch.delenv("AIIR_CASES_DIR", raising=False)
        with pytest.raises(SystemExit):
            get_case_dir()


class TestFindingsIO:
    def test_load_empty(self, case_dir):
        assert load_findings(case_dir) == []

    def test_save_and_load(self, case_dir):
        findings = [{"id": "F-001", "status": "DRAFT", "title": "Test"}]
        save_findings(case_dir, findings)
        loaded = load_findings(case_dir)
        assert len(loaded) == 1
        assert loaded[0]["id"] == "F-001"


class TestTimelineIO:
    def test_load_empty(self, case_dir):
        assert load_timeline(case_dir) == []

    def test_save_and_load(self, case_dir):
        events = [{"id": "T-001", "status": "DRAFT", "timestamp": "2026-01-01T00:00:00Z"}]
        save_timeline(case_dir, events)
        loaded = load_timeline(case_dir)
        assert len(loaded) == 1
        assert loaded[0]["id"] == "T-001"


class TestFindingsRegeneration:
    def test_draft_regen(self, case_dir):
        findings = [{
            "id": "F-001", "status": "DRAFT", "title": "Suspicious process",
            "confidence": "MEDIUM", "evidence_ids": ["wt-20260219-001"],
            "observation": "obs", "interpretation": "interp",
            "confidence_justification": "justified", "staged": "2026-02-19T10:00:00Z",
        }]
        regenerate_findings_md(case_dir, findings)
        md = (case_dir / "FINDINGS.md").read_text()
        assert "[DRAFT]" in md
        assert "awaiting human approval" in md

    def test_approved_regen(self, case_dir):
        findings = [{
            "id": "F-001", "status": "APPROVED", "title": "Confirmed finding",
            "confidence": "HIGH", "evidence_ids": ["wt-20260219-001"],
            "observation": "obs", "interpretation": "interp",
            "confidence_justification": "justified", "staged": "2026-02-19T10:00:00Z",
            "approved_by": "analyst1", "approved_at": "2026-02-19T12:00:00Z",
        }]
        regenerate_findings_md(case_dir, findings)
        md = (case_dir / "FINDINGS.md").read_text()
        assert "[APPROVED]" in md
        assert "APPROVED by analyst1 at 2026-02-19T12:00:00Z" in md

    def test_rejected_with_reason(self, case_dir):
        findings = [{
            "id": "F-001", "status": "REJECTED", "title": "Bad finding",
            "confidence": "LOW", "evidence_ids": [],
            "observation": "obs", "interpretation": "interp",
            "confidence_justification": "justified", "staged": "2026-02-19T10:00:00Z",
            "rejected_by": "analyst2", "rejected_at": "2026-02-19T13:00:00Z",
            "rejection_reason": "Insufficient evidence",
        }]
        regenerate_findings_md(case_dir, findings)
        md = (case_dir / "FINDINGS.md").read_text()
        assert "[REJECTED]" in md
        assert "reason: Insufficient evidence" in md

    def test_save_findings_triggers_regen(self, case_dir):
        findings = [{
            "id": "F-001", "status": "APPROVED", "title": "Test",
            "confidence": "HIGH", "evidence_ids": ["ev-001"],
            "observation": "obs", "interpretation": "interp",
            "confidence_justification": "justified", "staged": "2026-02-19T10:00:00Z",
            "approved_by": "analyst1", "approved_at": "2026-02-19T12:00:00Z",
        }]
        save_findings(case_dir, findings)
        md = (case_dir / "FINDINGS.md").read_text()
        assert "[APPROVED]" in md


class TestTimelineRegeneration:
    def test_regen_produces_correct_md(self, case_dir):
        timeline = [{
            "id": "T-001", "status": "DRAFT",
            "timestamp": "2026-02-19T10:30:00Z",
            "description": "First lateral movement detected",
            "evidence_ids": ["wt-20260219-001"],
            "source": "Event log analysis",
            "staged": "2026-02-19T11:00:00Z",
        }]
        regenerate_timeline_md(case_dir, timeline)
        md = (case_dir / "TIMELINE.md").read_text()
        assert "T-001" in md
        assert "[DRAFT]" in md
        assert "First lateral movement detected" in md
        assert "wt-20260219-001" in md
        assert "Event log analysis" in md


class TestApprovalLog:
    def test_write_approval(self, case_dir):
        identity = {"os_user": "testuser", "analyst": "analyst1", "analyst_source": "flag"}
        write_approval_log(case_dir, "F-001", "APPROVED", identity)
        log_file = case_dir / ".audit" / "approvals.jsonl"
        assert log_file.exists()
        entry = json.loads(log_file.read_text().strip())
        assert entry["item_id"] == "F-001"
        assert entry["action"] == "APPROVED"

    def test_write_rejection_with_reason(self, case_dir):
        identity = {"os_user": "testuser", "analyst": "analyst1", "analyst_source": "flag"}
        write_approval_log(case_dir, "F-002", "REJECTED", identity, reason="Bad evidence")
        log_file = case_dir / ".audit" / "approvals.jsonl"
        entry = json.loads(log_file.read_text().strip())
        assert entry["reason"] == "Bad evidence"
