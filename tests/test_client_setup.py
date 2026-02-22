"""Tests for aiir setup client command."""

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from aiir_cli.commands.client_setup import (
    _MSLEARN_MCP,
    _ZELTSER_MCP,
    _cmd_setup_client_remote,
    _discover_services,
    _ensure_mcp_path,
    _format_server_entry,
    _merge_and_write,
    _normalise_url,
    _probe_health_with_auth,
    _save_gateway_config,
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
            "no_mslearn": False,
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

    def test_mslearn_included_by_default(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        args = self._make_args()
        identity = {"examiner": "testuser"}
        cmd_setup_client(args, identity)

        data = json.loads((tmp_path / ".mcp.json").read_text())
        assert "microsoft-learn" in data["mcpServers"]
        assert data["mcpServers"]["microsoft-learn"]["url"] == _MSLEARN_MCP["url"]
        assert data["mcpServers"]["microsoft-learn"]["type"] == "streamable-http"

    def test_no_mslearn_flag(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        args = self._make_args(no_mslearn=True)
        identity = {"examiner": "testuser"}
        cmd_setup_client(args, identity)

        data = json.loads((tmp_path / ".mcp.json").read_text())
        assert "microsoft-learn" not in data["mcpServers"]
        # Zeltser still present
        assert "zeltser-ir-writing" in data["mcpServers"]

    def test_no_both_internet_mcps(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        args = self._make_args(no_zeltser=True, no_mslearn=True)
        identity = {"examiner": "testuser"}
        cmd_setup_client(args, identity)

        data = json.loads((tmp_path / ".mcp.json").read_text())
        assert "zeltser-ir-writing" not in data["mcpServers"]
        assert "microsoft-learn" not in data["mcpServers"]

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
        args = self._make_args(sift=None, no_zeltser=True, no_mslearn=True)
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
        assert "microsoft-learn" in content

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


class TestFormatServerEntry:
    def test_claude_code_with_token(self):
        entry = _format_server_entry("claude-code", "https://sift:4508/mcp", "tok123")
        assert entry["type"] == "streamable-http"
        assert entry["url"] == "https://sift:4508/mcp"
        assert entry["headers"]["Authorization"] == "Bearer tok123"

    def test_claude_desktop_uses_mcp_remote(self):
        entry = _format_server_entry("claude-desktop", "https://sift:4508/mcp", "tok123")
        assert entry["command"] == "npx"
        assert "mcp-remote" in entry["args"]
        assert "https://sift:4508/mcp" in entry["args"]
        assert entry["env"]["AUTH_HEADER"] == "Bearer tok123"

    def test_no_token(self):
        entry = _format_server_entry("claude-code", "https://sift:4508/mcp", None)
        assert entry["type"] == "streamable-http"
        assert "headers" not in entry

    def test_cursor_with_token(self):
        entry = _format_server_entry("cursor", "https://sift:4508/mcp", "tok")
        assert entry["type"] == "streamable-http"
        assert entry["headers"]["Authorization"] == "Bearer tok"


class TestRemoteSetup:
    def _make_args(self, **kwargs):
        import argparse
        defaults = {
            "client": "claude-code",
            "sift": "https://sift.example.com:4508",
            "windows": None,
            "remnux": None,
            "examiner": "testuser",
            "no_zeltser": True,
            "no_mslearn": True,
            "yes": True,
            "remote": True,
            "token": "aiir_gw_abc123",
        }
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    @patch("aiir_cli.commands.client_setup._probe_health_with_auth")
    @patch("aiir_cli.commands.client_setup._discover_services")
    @patch("aiir_cli.commands.client_setup._save_gateway_config")
    def test_remote_generates_per_backend_urls(self, mock_save, mock_discover, mock_probe, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        mock_probe.return_value = {"status": "ok"}
        mock_discover.return_value = [
            {"name": "forensic-mcp", "started": True, "type": "stdio"},
            {"name": "sift-mcp", "started": True, "type": "stdio"},
        ]
        args = self._make_args()
        identity = {"examiner": "testuser"}
        _cmd_setup_client_remote(args, identity)

        config_path = tmp_path / ".mcp.json"
        assert config_path.is_file()
        data = json.loads(config_path.read_text())

        # Aggregate endpoint
        assert "aiir" in data["mcpServers"]
        assert data["mcpServers"]["aiir"]["url"] == "https://sift.example.com:4508/mcp"
        assert data["mcpServers"]["aiir"]["headers"]["Authorization"] == "Bearer aiir_gw_abc123"

        # Per-backend endpoints
        assert "forensic-mcp" in data["mcpServers"]
        assert data["mcpServers"]["forensic-mcp"]["url"] == "https://sift.example.com:4508/mcp/forensic-mcp"
        assert "sift-mcp" in data["mcpServers"]
        assert data["mcpServers"]["sift-mcp"]["url"] == "https://sift.example.com:4508/mcp/sift-mcp"

    @patch("aiir_cli.commands.client_setup._probe_health_with_auth")
    @patch("aiir_cli.commands.client_setup._discover_services")
    @patch("aiir_cli.commands.client_setup._save_gateway_config")
    def test_remote_bearer_token_in_headers(self, mock_save, mock_discover, mock_probe, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        mock_probe.return_value = {"status": "ok"}
        mock_discover.return_value = [{"name": "forensic-mcp", "started": True}]
        args = self._make_args(token="secret_token_xyz")
        identity = {"examiner": "testuser"}
        _cmd_setup_client_remote(args, identity)

        data = json.loads((tmp_path / ".mcp.json").read_text())
        for name, entry in data["mcpServers"].items():
            if "headers" in entry:
                assert entry["headers"]["Authorization"] == "Bearer secret_token_xyz"

    @patch("aiir_cli.commands.client_setup._probe_health_with_auth")
    def test_remote_unreachable_gateway_exits(self, mock_probe, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        mock_probe.return_value = None
        args = self._make_args()
        identity = {"examiner": "testuser"}
        with pytest.raises(SystemExit):
            _cmd_setup_client_remote(args, identity)

    @patch("aiir_cli.commands.client_setup._probe_health_with_auth")
    @patch("aiir_cli.commands.client_setup._discover_services")
    @patch("aiir_cli.commands.client_setup._save_gateway_config")
    def test_remote_saves_gateway_config(self, mock_save, mock_discover, mock_probe, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        mock_probe.return_value = {"status": "ok"}
        mock_discover.return_value = [{"name": "forensic-mcp", "started": True}]
        args = self._make_args()
        identity = {"examiner": "testuser"}
        _cmd_setup_client_remote(args, identity)
        mock_save.assert_called_once_with("https://sift.example.com:4508", "aiir_gw_abc123")

    @patch("aiir_cli.commands.client_setup._probe_health_with_auth")
    @patch("aiir_cli.commands.client_setup._discover_services")
    @patch("aiir_cli.commands.client_setup._save_gateway_config")
    def test_remote_claude_desktop_uses_mcp_remote(self, mock_save, mock_discover, mock_probe, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("HOME", str(tmp_path))
        mock_probe.return_value = {"status": "ok"}
        mock_discover.return_value = [{"name": "forensic-mcp", "started": True}]
        args = self._make_args(client="claude-desktop")
        identity = {"examiner": "testuser"}
        _cmd_setup_client_remote(args, identity)

        config_path = tmp_path / ".config" / "claude" / "claude_desktop_config.json"
        assert config_path.is_file()
        data = json.loads(config_path.read_text())
        # Claude Desktop entries use mcp-remote bridge
        entry = data["mcpServers"]["forensic-mcp"]
        assert entry["command"] == "npx"
        assert "mcp-remote" in entry["args"]


class TestSaveGatewayConfig:
    def test_saves_to_config_yaml(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        # Patch Path.home() to use tmp_path
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        _save_gateway_config("https://sift:4508", "tok123")
        import yaml
        config = yaml.safe_load((tmp_path / ".aiir" / "config.yaml").read_text())
        assert config["gateway_url"] == "https://sift:4508"
        assert config["gateway_token"] == "tok123"

    def test_preserves_existing_keys(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        config_dir = tmp_path / ".aiir"
        config_dir.mkdir()
        import yaml
        (config_dir / "config.yaml").write_text(yaml.dump({"other_key": "value"}))
        _save_gateway_config("https://sift:4508", "tok")
        config = yaml.safe_load((config_dir / "config.yaml").read_text())
        assert config["other_key"] == "value"
        assert config["gateway_url"] == "https://sift:4508"
