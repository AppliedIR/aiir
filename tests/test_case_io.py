"""Tests for shared case I/O module."""

import json
import os
from pathlib import Path

import pytest

from aiir_cli.case_io import (
    get_case_dir,
    import_bundle,
    load_findings,
    save_findings,
    load_timeline,
    save_timeline,
    write_approval_log,
)


@pytest.fixture
def case_dir(tmp_path, monkeypatch):
    """Create a minimal case directory."""
    monkeypatch.setenv("AIIR_EXAMINER", "tester")
    exam_dir = tmp_path / "examiners" / "tester"
    exam_dir.mkdir(parents=True)
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


class TestNoMarkdownGeneration:
    def test_save_findings_does_not_create_md(self, case_dir):
        findings = [{"id": "F-001", "status": "DRAFT", "title": "Test"}]
        save_findings(case_dir, findings)
        assert not (case_dir / "FINDINGS.md").exists()

    def test_save_timeline_does_not_create_md(self, case_dir):
        events = [{"id": "T-001", "status": "DRAFT", "timestamp": "2026-01-01T00:00:00Z"}]
        save_timeline(case_dir, events)
        assert not (case_dir / "TIMELINE.md").exists()


class TestApprovalLog:
    def test_write_approval(self, case_dir):
        identity = {"os_user": "testuser", "examiner": "analyst1", "examiner_source": "flag", "analyst": "analyst1", "analyst_source": "flag"}
        write_approval_log(case_dir, "F-001", "APPROVED", identity)
        log_file = case_dir / "examiners" / "tester" / "approvals.jsonl"
        assert log_file.exists()
        entry = json.loads(log_file.read_text().strip())
        assert entry["item_id"] == "F-001"
        assert entry["action"] == "APPROVED"

    def test_write_rejection_with_reason(self, case_dir):
        identity = {"os_user": "testuser", "examiner": "analyst1", "examiner_source": "flag", "analyst": "analyst1", "analyst_source": "flag"}
        write_approval_log(case_dir, "F-002", "REJECTED", identity, reason="Bad evidence")
        log_file = case_dir / "examiners" / "tester" / "approvals.jsonl"
        entry = json.loads(log_file.read_text().strip())
        assert entry["reason"] == "Bad evidence"


class TestPathTraversal:
    """Verify path traversal is rejected in case_id and bundle examiner."""

    def test_case_id_dotdot_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path))
        with pytest.raises(SystemExit):
            get_case_dir("../../etc")

    def test_case_id_slash_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path))
        with pytest.raises(SystemExit):
            get_case_dir("foo/bar")

    def test_case_id_backslash_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_CASES_DIR", str(tmp_path))
        with pytest.raises(SystemExit):
            get_case_dir("foo\\bar")

    def test_bundle_examiner_traversal_rejected(self, case_dir, monkeypatch):
        import yaml
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        meta_file = case_dir / "CASE.yaml"
        meta_file.write_text(yaml.dump({"case_id": "INC-001"}))
        bundle = {
            "schema_version": 1,
            "case_id": "INC-001",
            "examiner": "../../etc",
            "findings": [],
        }
        result = import_bundle(case_dir, bundle)
        assert result["status"] == "error"
        assert "Invalid" in result["message"]

    def test_bundle_valid_examiner_accepted(self, case_dir, monkeypatch):
        import yaml
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        meta_file = case_dir / "CASE.yaml"
        meta_file.write_text(yaml.dump({"case_id": "INC-001"}))
        bundle = {
            "schema_version": 1,
            "case_id": "INC-001",
            "examiner": "alice",
            "findings": [{"id": "F-001", "status": "DRAFT"}],
            "timeline": [],
        }
        result = import_bundle(case_dir, bundle)
        assert result["status"] == "imported"


class TestIdentityLowercase:
    """Verify identity module lowercases examiner names."""

    def test_uppercase_examiner_lowercased(self, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "Jane.Doe")
        from aiir_cli.identity import get_examiner_identity
        identity = get_examiner_identity()
        assert identity["examiner"] == "jane.doe"

    def test_flag_override_lowercased(self, monkeypatch):
        monkeypatch.delenv("AIIR_EXAMINER", raising=False)
        monkeypatch.delenv("AIIR_ANALYST", raising=False)
        from aiir_cli.identity import get_examiner_identity
        identity = get_examiner_identity(flag_override="ALICE")
        assert identity["examiner"] == "alice"
