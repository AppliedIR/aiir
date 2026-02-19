"""Tests for approve and reject commands (hardened with /dev/tty)."""

import json
import os
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
import yaml

from air_cli.commands.approve import cmd_approve, _approve_specific
from air_cli.commands.reject import cmd_reject
from air_cli.case_io import load_findings, save_findings, load_timeline, save_timeline, load_approval_log


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
def config_path(tmp_path):
    return tmp_path / ".air" / "config.yaml"


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


def _mock_tty_confirm():
    """Return a mock that simulates /dev/tty confirming 'y'."""
    mock_tty = MagicMock()
    mock_tty.readline.return_value = "y\n"
    return mock_tty


class TestApproveSpecific:
    def test_approve_finding(self, case_dir, identity, staged_finding, config_path):
        mock_tty = _mock_tty_confirm()
        with patch("air_cli.approval_auth.open", return_value=mock_tty):
            _approve_specific(case_dir, ["F-001"], identity, config_path)
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "APPROVED"
        assert findings[0]["approved_by"] == identity

    def test_approve_timeline_event(self, case_dir, identity, staged_timeline, config_path):
        mock_tty = _mock_tty_confirm()
        with patch("air_cli.approval_auth.open", return_value=mock_tty):
            _approve_specific(case_dir, ["T-001"], identity, config_path)
        timeline = load_timeline(case_dir)
        assert timeline[0]["status"] == "APPROVED"

    def test_approve_nonexistent_id(self, case_dir, identity, staged_finding, capsys, config_path):
        # No confirmation needed — exits before reaching confirm
        _approve_specific(case_dir, ["F-999"], identity, config_path)
        captured = capsys.readouterr()
        assert "not found or not DRAFT" in captured.err

    def test_approve_already_approved(self, case_dir, identity, staged_finding, config_path):
        mock_tty = _mock_tty_confirm()
        with patch("air_cli.approval_auth.open", return_value=mock_tty):
            _approve_specific(case_dir, ["F-001"], identity, config_path)
        # Try approving again — should say "not found or not DRAFT"
        _approve_specific(case_dir, ["F-001"], identity, config_path)
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "APPROVED"

    def test_approval_log_written(self, case_dir, identity, staged_finding, config_path):
        mock_tty = _mock_tty_confirm()
        with patch("air_cli.approval_auth.open", return_value=mock_tty):
            _approve_specific(case_dir, ["F-001"], identity, config_path)
        log = load_approval_log(case_dir)
        assert len(log) == 1
        assert log[0]["item_id"] == "F-001"
        assert log[0]["action"] == "APPROVED"
        assert log[0]["analyst"] == "analyst1"
        assert log[0]["mode"] == "interactive"

    def test_approval_cancelled(self, case_dir, identity, staged_finding, config_path):
        mock_tty = MagicMock()
        mock_tty.readline.return_value = "n\n"
        with patch("air_cli.approval_auth.open", return_value=mock_tty):
            with pytest.raises(SystemExit):
                _approve_specific(case_dir, ["F-001"], identity, config_path)
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "DRAFT"


class TestApproveInteractive:
    def test_no_drafts(self, case_dir, identity, capsys, monkeypatch):
        save_findings(case_dir, [])
        save_timeline(case_dir, [])
        args = Namespace(ids=[], case=None, analyst=None)
        # Mock Path.home() to point to temp dir to avoid picking up real PIN
        with patch("air_cli.commands.approve.Path.home", return_value=case_dir.parent):
            cmd_approve(args, identity)
        captured = capsys.readouterr()
        assert "No staged items" in captured.out

    def test_interactive_approve_all(self, case_dir, identity, staged_finding, capsys):
        mock_tty = _mock_tty_confirm()
        args = Namespace(ids=[], case=None, analyst=None)
        # Simulate: Enter (approve), then tty confirmation
        with patch("builtins.input", side_effect=["", ""]):
            with patch("air_cli.commands.approve.Path.home", return_value=case_dir.parent):
                with patch("air_cli.approval_auth.open", return_value=mock_tty):
                    cmd_approve(args, identity)
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "APPROVED"


class TestReject:
    def test_reject_finding(self, case_dir, identity, staged_finding):
        mock_tty = _mock_tty_confirm()
        args = Namespace(ids=["F-001"], reason="Insufficient evidence", case=None, analyst=None)
        with patch("air_cli.commands.reject.Path.home", return_value=case_dir.parent):
            with patch("air_cli.approval_auth.open", return_value=mock_tty):
                cmd_reject(args, identity)
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "REJECTED"
        assert findings[0]["rejection_reason"] == "Insufficient evidence"

    def test_reject_writes_log(self, case_dir, identity, staged_finding):
        mock_tty = _mock_tty_confirm()
        args = Namespace(ids=["F-001"], reason="Bad data", case=None, analyst=None)
        with patch("air_cli.commands.reject.Path.home", return_value=case_dir.parent):
            with patch("air_cli.approval_auth.open", return_value=mock_tty):
                cmd_reject(args, identity)
        log = load_approval_log(case_dir)
        assert log[0]["action"] == "REJECTED"
        assert log[0]["reason"] == "Bad data"
        assert log[0]["mode"] == "interactive"

    def test_reject_nonexistent(self, case_dir, identity, staged_finding, capsys):
        args = Namespace(ids=["F-999"], reason="nope", case=None, analyst=None)
        with patch("air_cli.commands.reject.Path.home", return_value=case_dir.parent):
            cmd_reject(args, identity)
        captured = capsys.readouterr()
        assert "not found or not DRAFT" in captured.err

    def test_reject_no_reason(self, case_dir, identity, staged_finding):
        mock_tty = _mock_tty_confirm()
        args = Namespace(ids=["F-001"], reason="", case=None, analyst=None)
        with patch("air_cli.commands.reject.Path.home", return_value=case_dir.parent):
            with patch("air_cli.approval_auth.open", return_value=mock_tty):
                cmd_reject(args, identity)
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "REJECTED"
        log = load_approval_log(case_dir)
        assert "reason" not in log[0]  # Empty reason not stored
