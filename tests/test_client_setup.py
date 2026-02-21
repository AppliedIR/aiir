"""Tests for aiir setup client command."""

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from aiir_cli.commands.client_setup import (
    _ensure_mcp_path,
    _merge_and_write,
    _normalise_url,
    _wizard_client,
    cmd_setup_client,
)


class TestNormaliseUrl:
    def test_bare_ip(self):
        assert _normalise_url("192.168.1.20", 4624) == "http://192.168.1.20:4624"

    def test_ip_with_port(self):
        assert _normalise_url("10.0.0.1:9999", 4624) == "http://10.0.0.1:9999"

    def test_full_http_url(self):
        assert _normalise_url("http://10.0.0.1:4624", 4624) == "http://10.0.0.1:4624"

    def test_https_url(self):
        assert _normalise_url("https://example.com:443", 4624) == "https://example.com:443"

    def test_empty(self):
        assert _normalise_url("", 4624) == ""


class TestEnsureMcpPath:
    def test_adds_mcp(self):
        assert _ensure_mcp_path("http://127.0.0.1:4508") == "http://127.0.0.1:4508/mcp"

    def test_already_has_mcp(self):
        assert _ensure_mcp_path("http://127.0.0.1:4508/mcp") == "http://127.0.0.1:4508/mcp"

    def test_trailing_slash_stripped(self):
        assert _ensure_mcp_path("http://127.0.0.1:4508/") == "http://127.0.0.1:4508/mcp"


class TestMergeAndWrite:
    def test_creates_new_file(self, tmp_path):
        path = tmp_path / "config.json"
        config = {"mcpServers": {"aiir": {"type": "streamable-http", "url": "http://localhost:4508/mcp"}}}
        _merge_and_write(path, config)
        data = json.loads(path.read_text())
        assert "aiir" in data["mcpServers"]
        assert data["mcpServers"]["aiir"]["type"] == "streamable-http"

    def test_preserves_existing_servers(self, tmp_path):
        path = tmp_path / "config.json"
        existing = {"mcpServers": {"custom": {"type": "stdio", "command": "test"}}}
        path.write_text(json.dumps(existing))

        config = {"mcpServers": {"aiir": {"type": "streamable-http", "url": "http://localhost:4508/mcp"}}}
        _merge_and_write(path, config)
        data = json.loads(path.read_text())
        assert "custom" in data["mcpServers"]
        assert "aiir" in data["mcpServers"]

    def test_overwrites_aiir_server(self, tmp_path):
        path = tmp_path / "config.json"
        existing = {"mcpServers": {"aiir": {"type": "streamable-http", "url": "http://old:4508/mcp"}}}
        path.write_text(json.dumps(existing))

        config = {"mcpServers": {"aiir": {"type": "streamable-http", "url": "http://new:4508/mcp"}}}
        _merge_and_write(path, config)
        data = json.loads(path.read_text())
        assert data["mcpServers"]["aiir"]["url"] == "http://new:4508/mcp"

    def test_creates_parent_dirs(self, tmp_path):
        path = tmp_path / "subdir" / "deep" / "config.json"
        config = {"mcpServers": {"aiir": {"type": "streamable-http", "url": "http://x/mcp"}}}
        _merge_and_write(path, config)
        assert path.is_file()


class TestCmdSetupClient:
    def _make_args(self, **kwargs):
        """Build a namespace with defaults."""
        import argparse
        defaults = {
            "client": "claude-code",
            "sift": "http://127.0.0.1:4508",
            "windows": None,
            "remnux": None,
            "examiner": "testuser",
            "no_zeltser": False,
            "yes": True,
        }
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    def test_generates_claude_code_config(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        args = self._make_args()
        identity = {"examiner": "testuser"}
        cmd_setup_client(args, identity)

        config_path = tmp_path / ".mcp.json"
        assert config_path.is_file()
        data = json.loads(config_path.read_text())
        assert "aiir" in data["mcpServers"]
        assert data["mcpServers"]["aiir"]["url"] == "http://127.0.0.1:4508/mcp"
        assert data["mcpServers"]["aiir"]["type"] == "streamable-http"
        # Zeltser included by default
        assert "zeltser-ir-writing" in data["mcpServers"]

    def test_no_zeltser_flag(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        args = self._make_args(no_zeltser=True)
        identity = {"examiner": "testuser"}
        cmd_setup_client(args, identity)

        data = json.loads((tmp_path / ".mcp.json").read_text())
        assert "zeltser-ir-writing" not in data["mcpServers"]

    def test_windows_endpoint(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        args = self._make_args(windows="192.168.1.20:4624")
        identity = {"examiner": "testuser"}
        cmd_setup_client(args, identity)

        data = json.loads((tmp_path / ".mcp.json").read_text())
        assert "wintools-mcp" in data["mcpServers"]
        assert data["mcpServers"]["wintools-mcp"]["url"] == "http://192.168.1.20:4624/mcp"

    def test_remnux_endpoint(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        args = self._make_args(remnux="10.0.0.5")
        identity = {"examiner": "testuser"}
        cmd_setup_client(args, identity)

        data = json.loads((tmp_path / ".mcp.json").read_text())
        assert "remnux-mcp" in data["mcpServers"]
        assert data["mcpServers"]["remnux-mcp"]["url"] == "http://10.0.0.5:3000/mcp"

    def test_cursor_config(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        args = self._make_args(client="cursor")
        identity = {"examiner": "testuser"}
        cmd_setup_client(args, identity)

        config_path = tmp_path / ".cursor" / "mcp.json"
        assert config_path.is_file()
        data = json.loads(config_path.read_text())
        assert "aiir" in data["mcpServers"]

    def test_claude_desktop_config(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        # Redirect home to tmp_path so we don't write to real home
        monkeypatch.setenv("HOME", str(tmp_path))
        args = self._make_args(client="claude-desktop")
        identity = {"examiner": "testuser"}
        cmd_setup_client(args, identity)

        config_path = tmp_path / ".config" / "claude" / "claude_desktop_config.json"
        assert config_path.is_file()

    def test_no_endpoints_does_nothing(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        args = self._make_args(sift=None, no_zeltser=True)
        # Need to set sift to empty via the flag path
        args.sift = ""
        identity = {"examiner": "testuser"}
        cmd_setup_client(args, identity)

        assert not (tmp_path / ".mcp.json").exists()

    def test_merge_preserves_existing(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        # Pre-existing config
        existing = {"mcpServers": {"my-custom-mcp": {"type": "stdio", "command": "test"}}}
        (tmp_path / ".mcp.json").write_text(json.dumps(existing))

        args = self._make_args()
        identity = {"examiner": "testuser"}
        cmd_setup_client(args, identity)

        data = json.loads((tmp_path / ".mcp.json").read_text())
        assert "my-custom-mcp" in data["mcpServers"]
        assert "aiir" in data["mcpServers"]

    def test_librechat_config(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        args = self._make_args(client="librechat", windows="192.168.1.20:4624")
        identity = {"examiner": "testuser"}
        cmd_setup_client(args, identity)

        config_path = tmp_path / "librechat_mcp.yaml"
        assert config_path.is_file()
        content = config_path.read_text()
        assert "mcpServers:" in content
        assert 'type: "streamable-http"' in content
        assert 'url: "http://127.0.0.1:4508/mcp"' in content
        assert 'url: "http://192.168.1.20:4624/mcp"' in content
        assert "timeout: 60000" in content
        assert "zeltser-ir-writing" in content

    def test_librechat_no_json_merge(self, tmp_path, monkeypatch):
        """LibreChat writes YAML, not JSON — no .mcp.json created."""
        monkeypatch.chdir(tmp_path)
        args = self._make_args(client="librechat")
        identity = {"examiner": "testuser"}
        cmd_setup_client(args, identity)

        assert not (tmp_path / ".mcp.json").exists()
        assert (tmp_path / "librechat_mcp.yaml").is_file()


class TestWizardClient:
    def test_choice_4_maps_to_librechat(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _: "4")
        assert _wizard_client() == "librechat"

    def test_choice_5_maps_to_other(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _: "5")
        assert _wizard_client() == "other"

    def test_unrecognized_falls_back_to_other(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _: "99")
        assert _wizard_client() == "other"

    def test_empty_input_defaults_to_choice_1(self, monkeypatch):
        """Empty input uses prompt default '1', which maps to claude-code."""
        monkeypatch.setattr("builtins.input", lambda _: "")
        assert _wizard_client() == "claude-code"
