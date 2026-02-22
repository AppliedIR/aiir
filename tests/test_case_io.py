"""Tests for shared case I/O module."""

import json
import os
from pathlib import Path

import pytest

from aiir_cli.case_io import (
    compute_content_hash,
    export_bundle,
    get_case_dir,
    import_bundle,
    load_findings,
    save_findings,
    load_timeline,
    save_timeline,
    verify_approval_integrity,
    write_approval_log,
)


@pytest.fixture
def case_dir(tmp_path, monkeypatch):
    """Create a minimal flat case directory."""
    monkeypatch.setenv("AIIR_EXAMINER", "tester")
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
        findings = [{"id": "F-tester-001", "status": "DRAFT", "title": "Test"}]
        save_findings(case_dir, findings)
        loaded = load_findings(case_dir)
        assert len(loaded) == 1
        assert loaded[0]["id"] == "F-tester-001"


class TestTimelineIO:
    def test_load_empty(self, case_dir):
        assert load_timeline(case_dir) == []

    def test_save_and_load(self, case_dir):
        events = [{"id": "T-tester-001", "status": "DRAFT", "timestamp": "2026-01-01T00:00:00Z"}]
        save_timeline(case_dir, events)
        loaded = load_timeline(case_dir)
        assert len(loaded) == 1
        assert loaded[0]["id"] == "T-tester-001"


class TestNoMarkdownGeneration:
    def test_save_findings_does_not_create_md(self, case_dir):
        findings = [{"id": "F-tester-001", "status": "DRAFT", "title": "Test"}]
        save_findings(case_dir, findings)
        assert not (case_dir / "FINDINGS.md").exists()

    def test_save_timeline_does_not_create_md(self, case_dir):
        events = [{"id": "T-tester-001", "status": "DRAFT", "timestamp": "2026-01-01T00:00:00Z"}]
        save_timeline(case_dir, events)
        assert not (case_dir / "TIMELINE.md").exists()


class TestApprovalLog:
    def test_write_approval(self, case_dir):
        identity = {"os_user": "testuser", "examiner": "analyst1", "examiner_source": "flag", "analyst": "analyst1", "analyst_source": "flag"}
        write_approval_log(case_dir, "F-tester-001", "APPROVED", identity)
        log_file = case_dir / "approvals.jsonl"
        assert log_file.exists()
        entry = json.loads(log_file.read_text().strip())
        assert entry["item_id"] == "F-tester-001"
        assert entry["action"] == "APPROVED"

    def test_write_rejection_with_reason(self, case_dir):
        identity = {"os_user": "testuser", "examiner": "analyst1", "examiner_source": "flag", "analyst": "analyst1", "analyst_source": "flag"}
        write_approval_log(case_dir, "F-tester-002", "REJECTED", identity, reason="Bad evidence")
        log_file = case_dir / "approvals.jsonl"
        entry = json.loads(log_file.read_text().strip())
        assert entry["reason"] == "Bad evidence"


class TestPathTraversal:
    """Verify path traversal is rejected in case_id."""

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

    def test_import_bundle_merges(self, case_dir, monkeypatch):
        """import_bundle merges incoming items using last-write-wins."""
        import yaml
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        meta_file = case_dir / "CASE.yaml"
        meta_file.write_text(yaml.dump({"case_id": "INC-001"}))
        bundle = {
            "case_id": "INC-001",
            "examiner": "alice",
            "findings": [{"id": "F-alice-001", "title": "Alice's finding", "status": "DRAFT", "staged": "2026-01-01T00:00:00Z"}],
            "timeline": [],
        }
        result = import_bundle(case_dir, bundle)
        assert result["status"] == "merged"
        assert result["findings"]["added"] == 1

    def test_import_bundle_invalid_type(self, case_dir):
        result = import_bundle(case_dir, "not a dict")
        assert result["status"] == "error"


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


class TestContentHash:
    def test_deterministic(self):
        item = {"id": "F-tester-001", "title": "Test", "observation": "something"}
        h1 = compute_content_hash(item)
        h2 = compute_content_hash(item)
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex

    def test_excludes_volatile_fields(self):
        base = {"id": "F-tester-001", "title": "Test", "observation": "something"}
        h1 = compute_content_hash(base)
        with_volatile = dict(base, status="APPROVED", approved_at="2026-01-01",
                             approved_by="tester", content_hash="old", modified_at="2026-01-02")
        h2 = compute_content_hash(with_volatile)
        assert h1 == h2

    def test_detects_content_changes(self):
        item1 = {"id": "F-tester-001", "title": "Test", "observation": "original"}
        item2 = {"id": "F-tester-001", "title": "Test", "observation": "modified"}
        assert compute_content_hash(item1) != compute_content_hash(item2)


class TestContentHashIntegrity:
    """Tests that simulate the actual approve.py flow.

    approve.py loads via load_findings (flat case root), computes hash,
    then saves back with content_hash. verify_approval_integrity reloads
    and recomputes to verify.
    """

    def test_verify_detects_tampering(self, case_dir, monkeypatch):
        identity = {"os_user": "testuser", "examiner": "tester",
                    "examiner_source": "env"}
        # Save DRAFT finding
        save_findings(case_dir, [{"id": "F-tester-001", "title": "Test",
                                  "observation": "original", "status": "DRAFT"}])
        # Simulate approve: load, compute hash, save back
        findings = load_findings(case_dir)
        findings[0]["content_hash"] = compute_content_hash(findings[0])
        findings[0]["status"] = "APPROVED"
        save_findings(case_dir, findings)
        write_approval_log(case_dir, "F-tester-001", "APPROVED", identity)

        # Tamper with the finding after approval
        findings = load_findings(case_dir)
        findings[0]["observation"] = "tampered content"
        save_findings(case_dir, findings)

        results = verify_approval_integrity(case_dir)
        assert results[0]["verification"] == "tampered"

    def test_verify_confirmed_with_hash(self, case_dir, monkeypatch):
        identity = {"os_user": "testuser", "examiner": "tester",
                    "examiner_source": "env"}
        # Save DRAFT finding
        save_findings(case_dir, [{"id": "F-tester-001", "title": "Test",
                                  "observation": "original", "status": "DRAFT"}])
        # Simulate approve: load, compute hash, save back
        findings = load_findings(case_dir)
        findings[0]["content_hash"] = compute_content_hash(findings[0])
        findings[0]["status"] = "APPROVED"
        save_findings(case_dir, findings)
        write_approval_log(case_dir, "F-tester-001", "APPROVED", identity)

        results = verify_approval_integrity(case_dir)
        assert results[0]["verification"] == "confirmed"


class TestExportBundle:
    def test_export_includes_data(self, case_dir, monkeypatch):
        import yaml
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        (case_dir / "CASE.yaml").write_text(yaml.dump({"case_id": "INC-001"}))
        save_findings(case_dir, [{"id": "F-tester-001", "status": "DRAFT", "staged": "2026-01-01T00:00:00Z"}])
        save_timeline(case_dir, [{"id": "T-tester-001", "timestamp": "2026-01-01T00:00:00Z"}])
        bundle = export_bundle(case_dir)
        assert bundle["case_id"] == "INC-001"
        assert bundle["examiner"] == "tester"
        assert len(bundle["findings"]) == 1
        assert len(bundle["timeline"]) == 1

    def test_export_since_filter(self, case_dir, monkeypatch):
        import yaml
        monkeypatch.setenv("AIIR_EXAMINER", "tester")
        (case_dir / "CASE.yaml").write_text(yaml.dump({"case_id": "INC-001"}))
        save_findings(case_dir, [
            {"id": "F-tester-001", "status": "DRAFT", "staged": "2026-01-01T00:00:00Z"},
            {"id": "F-tester-002", "status": "DRAFT", "staged": "2026-06-01T00:00:00Z"},
        ])
        bundle = export_bundle(case_dir, since="2026-03-01T00:00:00Z")
        assert len(bundle["findings"]) == 1
        assert bundle["findings"][0]["id"] == "F-tester-002"


class TestImportBundle:
    def test_merge_adds_new(self, case_dir):
        bundle = {
            "findings": [{"id": "F-alice-001", "title": "New", "status": "DRAFT", "staged": "2026-01-01T00:00:00Z"}],
            "timeline": [],
        }
        result = import_bundle(case_dir, bundle)
        assert result["status"] == "merged"
        assert result["findings"]["added"] == 1

    def test_merge_updates_newer(self, case_dir):
        save_findings(case_dir, [{"id": "F-alice-001", "title": "Old", "staged": "2026-01-01T00:00:00Z"}])
        bundle = {
            "findings": [{"id": "F-alice-001", "title": "Updated", "staged": "2026-06-01T00:00:00Z"}],
        }
        result = import_bundle(case_dir, bundle)
        assert result["findings"]["updated"] == 1
        loaded = load_findings(case_dir)
        assert loaded[0]["title"] == "Updated"

    def test_merge_skips_older(self, case_dir):
        save_findings(case_dir, [{"id": "F-alice-001", "title": "Newer", "staged": "2026-06-01T00:00:00Z"}])
        bundle = {
            "findings": [{"id": "F-alice-001", "title": "Older", "staged": "2026-01-01T00:00:00Z"}],
        }
        result = import_bundle(case_dir, bundle)
        assert result["findings"]["skipped"] == 1
        loaded = load_findings(case_dir)
        assert loaded[0]["title"] == "Newer"

    def test_non_dict_returns_error(self, case_dir):
        result = import_bundle(case_dir, "not a dict")
        assert result["status"] == "error"
