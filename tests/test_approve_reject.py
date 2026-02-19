"""Tests for approve and reject commands."""

import json
import os
from argparse import Namespace
from pathlib import Path

import pytest
import yaml

from air_cli.commands.approve import cmd_approve, _approve_specific
from air_cli.commands.reject import cmd_reject
from air_cli.case_io import load_findings, save_findings, load_timeline, save_timeline


@pytest.fixture
def case_dir(tmp_path, monkeypatch):
    """Create a minimal case directory structure."""
    case_id = "INC-2026-TEST"
    case_path = tmp_path / case_id
    case_path.mkdir()
    (case_path / ".audit").mkdir()

    meta = {"case_id": case_id, "name": "Test", "status": "open"}
    with open(case_path / "CASE.yaml", "w") as f:
        yaml.dump(meta, f)

    with open(case_path / ".audit" / "evidence.json", "w") as f:
        json.dump({"files": []}, f)

    monkeypatch.setenv("AIR_CASE_DIR", str(case_path))
    return case_path


@pytest.fixture
def identity():
    return {"os_user": "testuser", "analyst": "analyst1", "analyst_source": "flag"}


@pytest.fixture
def staged_finding(case_dir):
    """Stage a DRAFT finding."""
    findings = [
        {
            "id": "F-001",
            "status": "DRAFT",
            "title": "Suspicious process",
            "confidence": "MEDIUM",
            "evidence_ids": ["ev-001"],
            "observation": "svchost from cmd",
            "interpretation": "unusual",
            "confidence_justification": "single source",
            "type": "finding",
            "staged": "2026-02-19T12:00:00Z",
        }
    ]
    save_findings(case_dir, findings)
    return findings


@pytest.fixture
def staged_timeline(case_dir):
    """Stage a DRAFT timeline event."""
    events = [
        {
            "id": "T-001",
            "status": "DRAFT",
            "timestamp": "2026-02-19T10:00:00Z",
            "description": "First lateral movement",
            "staged": "2026-02-19T12:00:00Z",
        }
    ]
    save_timeline(case_dir, events)
    return events


class TestApproveSpecific:
    def test_approve_finding(self, case_dir, identity, staged_finding):
        _approve_specific(case_dir, ["F-001"], identity)
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "APPROVED"
        assert findings[0]["approved_by"] == identity

    def test_approve_timeline_event(self, case_dir, identity, staged_timeline):
        _approve_specific(case_dir, ["T-001"], identity)
        timeline = load_timeline(case_dir)
        assert timeline[0]["status"] == "APPROVED"

    def test_approve_nonexistent_id(self, case_dir, identity, staged_finding, capsys):
        _approve_specific(case_dir, ["F-999"], identity)
        captured = capsys.readouterr()
        assert "not found or not DRAFT" in captured.err

    def test_approve_already_approved(self, case_dir, identity, staged_finding):
        _approve_specific(case_dir, ["F-001"], identity)
        # Try approving again — should say "not found or not DRAFT"
        _approve_specific(case_dir, ["F-001"], identity)
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "APPROVED"

    def test_approval_log_written(self, case_dir, identity, staged_finding):
        _approve_specific(case_dir, ["F-001"], identity)
        log_file = case_dir / ".audit" / "approvals.jsonl"
        assert log_file.exists()
        entry = json.loads(log_file.read_text().strip())
        assert entry["item_id"] == "F-001"
        assert entry["action"] == "APPROVED"
        assert entry["analyst"] == "analyst1"


class TestReject:
    def test_reject_finding(self, case_dir, identity, staged_finding):
        args = Namespace(ids=["F-001"], reason="Insufficient evidence", case=None)
        cmd_reject(args, identity)
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "REJECTED"
        assert findings[0]["rejection_reason"] == "Insufficient evidence"

    def test_reject_writes_log(self, case_dir, identity, staged_finding):
        args = Namespace(ids=["F-001"], reason="Bad data", case=None)
        cmd_reject(args, identity)
        log_file = case_dir / ".audit" / "approvals.jsonl"
        entry = json.loads(log_file.read_text().strip())
        assert entry["action"] == "REJECTED"
        assert entry["reason"] == "Bad data"

    def test_reject_nonexistent(self, case_dir, identity, staged_finding, capsys):
        args = Namespace(ids=["F-999"], reason="nope", case=None)
        cmd_reject(args, identity)
        captured = capsys.readouterr()
        assert "not found or not DRAFT" in captured.err
