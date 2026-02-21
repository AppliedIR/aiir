"""Tests for aiir sync export/import commands."""

import argparse
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from aiir_cli.commands.sync import cmd_sync


def _init_case(case_dir: Path, examiner: str = "alice") -> None:
    """Set up a minimal case directory for testing."""
    meta = {"case_id": "INC-2026-0001", "name": "Test Case", "mode": "solo"}
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "CASE.yaml").write_text(json.dumps(meta))

    exam_dir = case_dir / "examiners" / examiner
    exam_dir.mkdir(parents=True)
    (exam_dir / "audit").mkdir()
    (exam_dir / "findings.json").write_text(json.dumps([
        {"id": "F-001", "title": "Malware found", "status": "DRAFT"},
    ]))
    (exam_dir / "timeline.json").write_text(json.dumps([
        {"id": "T-001", "timestamp": "2026-01-01T00:00:00Z", "description": "First event"},
    ]))
    (exam_dir / "todos.json").write_text(json.dumps([]))
    (exam_dir / "approvals.jsonl").write_text("")


def _make_args(**kwargs):
    defaults = {"sync_action": None, "case": None, "file": ""}
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


class TestSyncExport:
    def test_export_writes_bundle(self, tmp_path, monkeypatch):
        case_dir = tmp_path / "case"
        _init_case(case_dir)
        monkeypatch.setenv("AIIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("AIIR_EXAMINER", "alice")

        output = tmp_path / "bundle.json"
        args = _make_args(sync_action="export", file=str(output))
        cmd_sync(args, {"examiner": "alice"})

        assert output.is_file()
        bundle = json.loads(output.read_text())
        assert bundle["examiner"] == "alice"
        assert bundle["case_id"] == "INC-2026-0001"
        assert len(bundle["findings"]) == 1
        assert bundle["findings"][0]["id"] == "F-001"

    def test_export_no_file_exits(self, tmp_path, monkeypatch):
        case_dir = tmp_path / "case"
        _init_case(case_dir)
        monkeypatch.setenv("AIIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("AIIR_EXAMINER", "alice")

        args = _make_args(sync_action="export", file="")
        with pytest.raises(SystemExit):
            cmd_sync(args, {"examiner": "alice"})


class TestSyncImport:
    def test_import_reads_bundle(self, tmp_path, monkeypatch):
        case_dir = tmp_path / "case"
        _init_case(case_dir, examiner="alice")
        monkeypatch.setenv("AIIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("AIIR_EXAMINER", "alice")

        bundle = {
            "schema_version": 1,
            "case_id": "INC-2026-0001",
            "examiner": "bob",
            "findings": [{"id": "F-001", "title": "Bob's finding", "status": "DRAFT"}],
            "timeline": [],
            "todos": [],
            "approvals": [],
        }
        bundle_file = tmp_path / "bob-bundle.json"
        bundle_file.write_text(json.dumps(bundle))

        args = _make_args(sync_action="import", file=str(bundle_file))
        cmd_sync(args, {"examiner": "alice"})

        bob_dir = case_dir / "examiners" / "bob"
        assert bob_dir.is_dir()
        imported = json.loads((bob_dir / "findings.json").read_text())
        assert len(imported) == 1
        assert imported[0]["title"] == "Bob's finding"

    def test_import_missing_file_exits(self, tmp_path, monkeypatch):
        case_dir = tmp_path / "case"
        _init_case(case_dir)
        monkeypatch.setenv("AIIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("AIIR_EXAMINER", "alice")

        args = _make_args(sync_action="import", file=str(tmp_path / "nonexistent.json"))
        with pytest.raises(SystemExit):
            cmd_sync(args, {"examiner": "alice"})

    def test_import_no_file_flag_exits(self, tmp_path, monkeypatch):
        case_dir = tmp_path / "case"
        _init_case(case_dir)
        monkeypatch.setenv("AIIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("AIIR_EXAMINER", "alice")

        args = _make_args(sync_action="import", file="")
        with pytest.raises(SystemExit):
            cmd_sync(args, {"examiner": "alice"})


class TestSyncDispatch:
    def test_no_action_prints_usage(self, capsys):
        args = _make_args(sync_action=None)
        with pytest.raises(SystemExit):
            cmd_sync(args, {"examiner": "alice"})
        assert "Usage" in capsys.readouterr().err
