"""Tests for shared case I/O module."""

import json
import os
from pathlib import Path

import pytest

from air_cli.case_io import (
    get_case_dir,
    load_findings,
    save_findings,
    load_timeline,
    save_timeline,
    write_approval_log,
)


@pytest.fixture
def case_dir(tmp_path):
    """Create a minimal case directory."""
    audit_dir = tmp_path / ".audit"
    audit_dir.mkdir()
    return tmp_path


class TestGetCaseDir:
    def test_from_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIR_CASE_DIR", str(tmp_path))
        assert get_case_dir() == tmp_path

    def test_from_explicit_id(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIR_CASES_DIR", str(tmp_path))
        case = tmp_path / "INC-TEST"
        case.mkdir()
        result = get_case_dir("INC-TEST")
        assert result == case

    def test_no_case_exits(self, monkeypatch):
        monkeypatch.delenv("AIR_CASE_DIR", raising=False)
        monkeypatch.delenv("AIR_CASES_DIR", raising=False)
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
