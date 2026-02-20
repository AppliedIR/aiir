"""Tests for review command views."""

import json
from argparse import Namespace
from pathlib import Path

import pytest
import yaml

from aiir_cli.commands.review import cmd_review, _extract_iocs_from_findings, _extract_text_iocs
from aiir_cli.case_io import save_findings, save_timeline, write_approval_log, verify_approval_integrity


@pytest.fixture
def case_dir(tmp_path, monkeypatch):
    """Create a minimal case directory structure."""
    case_id = "INC-2026-TEST"
    case_path = tmp_path / case_id
    case_path.mkdir()

    monkeypatch.setenv("AIIR_EXAMINER", "tester")

    meta = {"case_id": case_id, "name": "Test Case", "status": "open", "created": "2026-02-19",
            "examiner": "tester", "team": ["tester"]}
    with open(case_path / "CASE.yaml", "w") as f:
        yaml.dump(meta, f)

    exam_dir = case_path / "examiners" / "tester"
    exam_dir.mkdir(parents=True)
    with open(exam_dir / "evidence.json", "w") as f:
        json.dump({"files": []}, f)

    monkeypatch.setenv("AIIR_CASE_DIR", str(case_path))
    return case_path


@pytest.fixture
def identity():
    return {"os_user": "testuser", "examiner": "analyst1", "examiner_source": "flag",
            "analyst": "analyst1", "analyst_source": "flag"}


@pytest.fixture
def sample_findings(case_dir):
    findings = [
        {
            "id": "F-001",
            "status": "APPROVED",
            "title": "Lateral movement via PsExec",
            "confidence": "HIGH",
            "evidence_ids": ["ev-001", "ev-002"],
            "observation": "PsExec executed from 192.168.1.50 to target host",
            "interpretation": "Attacker moved laterally",
            "iocs": {
                "IPv4": ["192.168.1.50", "10.0.0.15"],
                "Domain": ["evil.example.com"],
                "File": ["C:\\Windows\\Temp\\payload.exe"],
            },
        },
        {
            "id": "F-002",
            "status": "DRAFT",
            "title": "Suspicious scheduled task",
            "confidence": "MEDIUM",
            "evidence_ids": ["ev-003"],
            "observation": "Observed connection to 172.16.0.99",
            "interpretation": "Possible persistence",
            "iocs": {"IPv4": ["172.16.0.99"]},
        },
        {
            "id": "F-003",
            "status": "REJECTED",
            "title": "Potential data staging",
            "confidence": "LOW",
            "evidence_ids": [],
            "observation": "Files found in temp directory",
            "interpretation": "Benign activity",
        },
    ]
    save_findings(case_dir, findings)
    return findings


@pytest.fixture
def sample_timeline(case_dir):
    events = [
        {
            "id": "T-001",
            "status": "APPROVED",
            "timestamp": "2026-02-19T10:00:00Z",
            "description": "Initial access via phishing email",
            "evidence_ids": ["ev-001"],
        },
        {
            "id": "T-002",
            "status": "DRAFT",
            "timestamp": "2026-02-19T11:00:00Z",
            "description": "Lateral movement detected",
        },
    ]
    save_timeline(case_dir, events)
    return events


class TestFindingsTable:
    def test_findings_table(self, case_dir, sample_findings, capsys):
        args = Namespace(case=None, findings=True, detail=False, verify=False, iocs=False,
                         timeline=False, audit=False, evidence=False, limit=50)
        cmd_review(args, {})
        output = capsys.readouterr().out
        assert "F-001" in output
        assert "APPROVED" in output
        assert "HIGH" in output
        assert "Lateral movement" in output

    def test_findings_empty(self, case_dir, capsys):
        save_findings(case_dir, [])
        args = Namespace(case=None, findings=True, detail=False, verify=False, iocs=False,
                         timeline=False, audit=False, evidence=False, limit=50)
        cmd_review(args, {})
        output = capsys.readouterr().out
        assert "No findings" in output


class TestFindingsDetail:
    def test_detail_shows_all_fields(self, case_dir, sample_findings, capsys):
        args = Namespace(case=None, findings=True, detail=True, verify=False, iocs=False,
                         timeline=False, audit=False, evidence=False, limit=50)
        cmd_review(args, {})
        output = capsys.readouterr().out
        assert "F-001" in output
        assert "Observation:" in output
        assert "Interpretation:" in output
        assert "Evidence:" in output


class TestFindingsVerify:
    def test_verified_finding(self, case_dir, sample_findings, identity, capsys):
        # Write approval record for F-001
        write_approval_log(case_dir, "F-001", "APPROVED", identity, mode="interactive")
        args = Namespace(case=None, findings=True, detail=False, verify=True, iocs=False,
                         timeline=False, audit=False, evidence=False, limit=50)
        cmd_review(args, {})
        output = capsys.readouterr().out
        assert "confirmed" in output
        assert "F-001" in output

    def test_unverified_finding(self, case_dir, sample_findings, capsys):
        # F-001 is APPROVED but no approval record exists
        args = Namespace(case=None, findings=True, detail=False, verify=True, iocs=False,
                         timeline=False, audit=False, evidence=False, limit=50)
        cmd_review(args, {})
        output = capsys.readouterr().out
        assert "NO APPROVAL RECORD" in output

    def test_draft_no_check(self, case_dir, capsys):
        save_findings(case_dir, [{"id": "F-010", "status": "DRAFT", "title": "Test"}])
        args = Namespace(case=None, findings=True, detail=False, verify=True, iocs=False,
                         timeline=False, audit=False, evidence=False, limit=50)
        cmd_review(args, {})
        output = capsys.readouterr().out
        assert "draft" in output


class TestVerifyIntegrity:
    def test_confirmed(self, case_dir, identity):
        save_findings(case_dir, [{"id": "F-001", "status": "APPROVED", "title": "Test"}])
        write_approval_log(case_dir, "F-001", "APPROVED", identity)
        results = verify_approval_integrity(case_dir)
        assert results[0]["verification"] == "confirmed"

    def test_no_record(self, case_dir):
        save_findings(case_dir, [{"id": "F-001", "status": "APPROVED", "title": "Test"}])
        results = verify_approval_integrity(case_dir)
        assert results[0]["verification"] == "no approval record"

    def test_mismatched_action(self, case_dir, identity):
        save_findings(case_dir, [{"id": "F-001", "status": "APPROVED", "title": "Test"}])
        write_approval_log(case_dir, "F-001", "REJECTED", identity)
        results = verify_approval_integrity(case_dir)
        assert results[0]["verification"] == "no approval record"

    def test_draft_unverified(self, case_dir):
        save_findings(case_dir, [{"id": "F-001", "status": "DRAFT", "title": "Test"}])
        results = verify_approval_integrity(case_dir)
        assert results[0]["verification"] == "draft"


class TestIOCExtraction:
    def test_structured_iocs(self, case_dir, sample_findings, capsys):
        args = Namespace(case=None, findings=False, detail=False, verify=False, iocs=True,
                         timeline=False, audit=False, evidence=False, limit=50)
        cmd_review(args, {})
        output = capsys.readouterr().out
        assert "Approved Findings" in output
        assert "192.168.1.50" in output
        assert "evil.example.com" in output
        assert "Draft Findings" in output
        assert "172.16.0.99" in output

    def test_extract_from_dict_iocs(self):
        findings = [{"iocs": {"IPv4": ["1.2.3.4"], "Domain": ["bad.com"]}, "observation": "", "interpretation": ""}]
        result = _extract_iocs_from_findings(findings)
        assert "1.2.3.4" in result["IPv4"]
        assert "bad.com" in result["Domain"]

    def test_extract_from_list_iocs(self):
        findings = [{"iocs": [{"type": "IPv4", "value": "5.6.7.8"}], "observation": "", "interpretation": ""}]
        result = _extract_iocs_from_findings(findings)
        assert "5.6.7.8" in result["IPv4"]

    def test_extract_text_ipv4(self):
        collected = {}
        _extract_text_iocs("Connected to 10.20.30.40 from source", collected)
        assert "10.20.30.40" in collected["IPv4"]

    def test_extract_text_sha256(self):
        collected = {}
        h = "a" * 64
        _extract_text_iocs(f"Hash: {h}", collected)
        assert h in collected["SHA256"]

    def test_extract_text_windows_path(self):
        collected = {}
        _extract_text_iocs(r"Found at C:\Windows\Temp\evil.exe on disk", collected)
        assert r"C:\Windows\Temp\evil.exe" in collected["File"]

    def test_extract_text_domain(self):
        collected = {}
        _extract_text_iocs("Resolved evil.example.com via DNS", collected)
        assert "evil.example.com" in collected["Domain"]

    def test_no_iocs(self, case_dir, capsys):
        save_findings(case_dir, [{"id": "F-001", "status": "DRAFT", "title": "Nothing", "observation": "clean", "interpretation": "benign"}])
        args = Namespace(case=None, findings=False, detail=False, verify=False, iocs=True,
                         timeline=False, audit=False, evidence=False, limit=50)
        cmd_review(args, {})
        output = capsys.readouterr().out
        assert "No IOCs" in output


class TestTimeline:
    def test_timeline_summary(self, case_dir, sample_timeline, capsys):
        args = Namespace(case=None, findings=False, detail=False, verify=False, iocs=False,
                         timeline=True, audit=False, evidence=False, limit=50)
        cmd_review(args, {})
        output = capsys.readouterr().out
        assert "T-001" in output
        assert "APPROVED" in output

    def test_timeline_detail(self, case_dir, sample_timeline, capsys):
        args = Namespace(case=None, findings=False, detail=True, verify=False, iocs=False,
                         timeline=True, audit=False, evidence=False, limit=50)
        cmd_review(args, {})
        output = capsys.readouterr().out
        assert "Description:" in output
        assert "Initial access" in output

    def test_timeline_empty(self, case_dir, capsys):
        save_timeline(case_dir, [])
        args = Namespace(case=None, findings=False, detail=False, verify=False, iocs=False,
                         timeline=True, audit=False, evidence=False, limit=50)
        cmd_review(args, {})
        output = capsys.readouterr().out
        assert "No timeline" in output


class TestSummary:
    def test_summary_shows_counts(self, case_dir, sample_findings, sample_timeline, capsys):
        args = Namespace(case=None, findings=False, detail=False, verify=False, iocs=False,
                         timeline=False, audit=False, evidence=False, limit=50)
        cmd_review(args, {})
        output = capsys.readouterr().out
        assert "1 draft" in output
        assert "1 approved" in output
        assert "1 rejected" in output
