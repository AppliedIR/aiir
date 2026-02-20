"""Tests for evidence CLI commands."""

import json
import os
import stat
from pathlib import Path

import pytest

from aiir_cli.commands.evidence import cmd_lock_evidence, cmd_register_evidence


@pytest.fixture
def case_dir(tmp_path, monkeypatch):
    """Create case dir with evidence directory and local store."""
    monkeypatch.setenv("AIIR_EXAMINER", "tester")
    (tmp_path / "evidence").mkdir()
    (tmp_path / "examiners" / "tester").mkdir(parents=True)
    (tmp_path / "examiners" / "tester" / "evidence.json").write_text('{"files": []}')
    return tmp_path


@pytest.fixture
def identity():
    return {"os_user": "testuser", "examiner": "analyst1", "examiner_source": "flag", "analyst": "analyst1", "analyst_source": "flag"}


class FakeArgs:
    def __init__(self, case=None, path=None, description=""):
        self.case = case
        self.path = path
        self.description = description


class TestLockEvidence:
    def test_lock_sets_444_perms(self, case_dir, identity, monkeypatch):
        monkeypatch.setenv("AIIR_CASE_DIR", str(case_dir))
        ev_file = case_dir / "evidence" / "sample.bin"
        ev_file.write_bytes(b"evidence data")
        cmd_lock_evidence(FakeArgs(), identity)
        mode = ev_file.stat().st_mode
        assert mode & stat.S_IWUSR == 0  # no write
        assert mode & stat.S_IRUSR != 0  # has read


class TestRegisterEvidence:
    def test_register_updates_evidence_json(self, case_dir, identity, monkeypatch):
        monkeypatch.setenv("AIIR_CASE_DIR", str(case_dir))
        ev_file = case_dir / "evidence" / "malware.bin"
        ev_file.write_bytes(b"malware content")
        args = FakeArgs(path=str(ev_file), description="Test malware")
        cmd_register_evidence(args, identity)
        reg = json.loads((case_dir / "examiners" / "tester" / "evidence.json").read_text())
        assert len(reg["files"]) == 1
        assert reg["files"][0]["sha256"]
        assert reg["files"][0]["description"] == "Test malware"

    def test_register_sets_readonly(self, case_dir, identity, monkeypatch):
        monkeypatch.setenv("AIIR_CASE_DIR", str(case_dir))
        ev_file = case_dir / "evidence" / "data.bin"
        ev_file.write_bytes(b"data")
        args = FakeArgs(path=str(ev_file))
        cmd_register_evidence(args, identity)
        assert not os.access(ev_file, os.W_OK)
