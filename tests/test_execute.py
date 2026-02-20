"""Tests for air exec command."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from air_cli.commands.execute import cmd_exec


@pytest.fixture
def case_dir(tmp_path):
    """Create a case directory with required structure."""
    (tmp_path / ".audit").mkdir()
    (tmp_path / "ACTIONS.md").write_text("# Actions Log\n\n")
    return tmp_path


@pytest.fixture
def identity():
    return {"os_user": "testuser", "analyst": "analyst1", "analyst_source": "flag"}


class FakeArgs:
    def __init__(self, cmd, purpose, case=None):
        self.cmd = cmd
        self.purpose = purpose
        self.case = case


class TestExec:
    def test_audit_written_on_exec(self, case_dir, identity, monkeypatch):
        monkeypatch.setenv("AIR_CASE_DIR", str(case_dir))
        args = FakeArgs(cmd=["echo", "hello"], purpose="test command")
        with patch("builtins.input", return_value="y"):
            cmd_exec(args, identity)
        log_file = case_dir / ".audit" / "exec.jsonl"
        assert log_file.exists()
        entry = json.loads(log_file.read_text().strip())
        assert entry["command"] == "echo hello"
        assert entry["purpose"] == "test command"
        assert entry["analyst"] == "analyst1"

    def test_cancelled_exec_writes_nothing(self, case_dir, identity, monkeypatch):
        monkeypatch.setenv("AIR_CASE_DIR", str(case_dir))
        args = FakeArgs(cmd=["echo", "hello"], purpose="test")
        with patch("builtins.input", return_value="n"):
            cmd_exec(args, identity)
        log_file = case_dir / ".audit" / "exec.jsonl"
        assert not log_file.exists()

    def test_actions_md_appended(self, case_dir, identity, monkeypatch):
        monkeypatch.setenv("AIR_CASE_DIR", str(case_dir))
        args = FakeArgs(cmd=["echo", "hello"], purpose="test output")
        with patch("builtins.input", return_value="y"):
            cmd_exec(args, identity)
        md = (case_dir / "ACTIONS.md").read_text()
        assert "test output" in md
        assert "analyst1" in md
        assert "`echo hello`" in md
