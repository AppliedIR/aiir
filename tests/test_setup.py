"""Tests for aiir setup command."""

from __future__ import annotations

import json
import stat
from unittest.mock import MagicMock, patch

import pytest
import yaml

from aiir_cli.commands.setup import cmd_setup
from aiir_cli.setup.config_gen import (
    generate_gateway_yaml,
    generate_mcp_json,
)
from aiir_cli.setup.detect import MCP_SERVERS, detect_installed_mcps, detect_venv_mcps
from aiir_cli.setup.wizard import wizard_clients

# -- Fixtures --


@pytest.fixture
def sample_mcps():
    return [
        {
            "name": "forensic-mcp",
            "python_path": "/usr/bin/python3",
            "module": "forensic_mcp",
        },
        {"name": "sift-mcp", "python_path": "/usr/bin/python3", "module": "sift_mcp"},
    ]


@pytest.fixture
def opencti_mcp():
    return {
        "name": "opencti-mcp",
        "python_path": "/usr/bin/python3",
        "module": "opencti_mcp",
    }


@pytest.fixture
def opencti_config():
    return {
        "url": "https://opencti.example.com",
        "token": "secret123",
        "ssl_verify": True,
    }


@pytest.fixture
def identity():
    return {"os_user": "testuser", "analyst": "analyst1", "analyst_source": "flag"}


# -- Detection tests --


class TestDetection:
    def test_detect_installed_returns_all_known(self):
        """detect_installed_mcps returns one entry per known MCP."""
        with patch("aiir_cli.setup.detect._check_module", return_value=False):
            results = detect_installed_mcps()
        names = {r["name"] for r in results}
        assert names == set(MCP_SERVERS.keys())

    def test_detect_installed_marks_available(self):
        with patch("aiir_cli.setup.detect._check_module", return_value=True):
            results = detect_installed_mcps()
        assert all(r["available"] for r in results)

    def test_detect_venv_finds_venv(self, tmp_path):
        """Finds MCPs installed in venvs."""
        venv_python = tmp_path / "forensic-mcp" / ".venv" / "bin" / "python"
        venv_python.parent.mkdir(parents=True)
        venv_python.touch()
        with patch("aiir_cli.setup.detect._check_module", return_value=True):
            results = detect_venv_mcps(search_dirs=[tmp_path])
        assert len(results) == 1
        assert results[0]["name"] == "forensic-mcp"
        assert "venv_path" in results[0]

    def test_detect_venv_shared_venv(self, tmp_path):
        """Finds MCPs via shared venv at base_dir/.venv/."""
        shared_python = tmp_path / ".venv" / "bin" / "python"
        shared_python.parent.mkdir(parents=True)
        shared_python.touch()
        with patch("aiir_cli.setup.detect._check_module", return_value=True):
            results = detect_venv_mcps(search_dirs=[tmp_path])
        names = {r["name"] for r in results}
        assert names == set(MCP_SERVERS.keys())
        # All should point to the shared python
        for r in results:
            assert r["python_path"] == str(shared_python)

    def test_detect_venv_shared_skips_per_repo(self, tmp_path):
        """When shared venv exists, per-repo venvs are not checked."""
        shared_python = tmp_path / ".venv" / "bin" / "python"
        shared_python.parent.mkdir(parents=True)
        shared_python.touch()
        # Also create a per-repo venv (should be ignored)
        per_repo = tmp_path / "forensic-mcp" / ".venv" / "bin" / "python"
        per_repo.parent.mkdir(parents=True)
        per_repo.touch()
        with patch("aiir_cli.setup.detect._check_module", return_value=True):
            results = detect_venv_mcps(search_dirs=[tmp_path])
        # Should all be shared, not per-repo
        for r in results:
            assert r["python_path"] == str(shared_python)

    def test_detect_venv_shared_unavailable_excluded(self, tmp_path):
        """Shared venv only includes MCPs that are actually importable."""
        shared_python = tmp_path / ".venv" / "bin" / "python"
        shared_python.parent.mkdir(parents=True)
        shared_python.touch()
        with patch("aiir_cli.setup.detect._check_module", return_value=False):
            results = detect_venv_mcps(search_dirs=[tmp_path])
        # None importable, so none returned
        assert results == []

    def test_detect_venv_empty_when_no_dirs(self, tmp_path):
        nonexistent = tmp_path / "nowhere"
        results = detect_venv_mcps(search_dirs=[nonexistent])
        assert results == []


# -- Config generation tests --


class TestConfigGen:
    def test_generate_mcp_json_basic(self, tmp_path, sample_mcps):
        output = tmp_path / ".mcp.json"
        generate_mcp_json(sample_mcps, output)
        config = json.loads(output.read_text())
        assert "mcpServers" in config
        assert "forensic-mcp" in config["mcpServers"]
        assert config["mcpServers"]["forensic-mcp"]["args"] == ["-m", "forensic_mcp"]

    def test_generate_mcp_json_opencti_env(
        self, tmp_path, sample_mcps, opencti_mcp, opencti_config
    ):
        mcps = sample_mcps + [opencti_mcp]
        output = tmp_path / ".mcp.json"
        generate_mcp_json(mcps, output, opencti_config)
        config = json.loads(output.read_text())
        octi = config["mcpServers"]["opencti-mcp"]
        assert octi["env"]["OPENCTI_URL"] == "https://opencti.example.com"
        assert octi["env"]["OPENCTI_TOKEN"] == "secret123"

    def test_generate_mcp_json_opencti_ssl_false(self, tmp_path, opencti_mcp):
        config = {"url": "https://x.com", "token": "t", "ssl_verify": False}
        output = tmp_path / ".mcp.json"
        generate_mcp_json([opencti_mcp], output, config)
        data = json.loads(output.read_text())
        assert data["mcpServers"]["opencti-mcp"]["env"]["OPENCTI_SSL_VERIFY"] == "false"

    def test_generate_mcp_json_permissions(self, tmp_path, sample_mcps):
        output = tmp_path / ".mcp.json"
        generate_mcp_json(sample_mcps, output)
        mode = output.stat().st_mode
        assert mode & stat.S_IRUSR  # owner read
        assert mode & stat.S_IWUSR  # owner write
        assert not (mode & stat.S_IRGRP)  # no group read
        assert not (mode & stat.S_IROTH)  # no other read

    def test_generate_desktop_uses_mcp_json(self, tmp_path, sample_mcps):
        output = tmp_path / "desktop.json"
        generate_mcp_json(sample_mcps, output)
        config = json.loads(output.read_text())
        assert "mcpServers" in config

    def test_generate_gateway_yaml_basic(self, tmp_path, sample_mcps):
        output = tmp_path / "gateway.yaml"
        generate_gateway_yaml(sample_mcps, output)
        config = yaml.safe_load(output.read_text())
        assert config["gateway"]["port"] == 4508
        assert "forensic-mcp" in config["backends"]
        assert config["backends"]["forensic-mcp"]["type"] == "stdio"

    def test_generate_gateway_yaml_remnux(self, tmp_path, sample_mcps):
        remnux = {"host": "192.168.1.100", "port": 8080, "token": "mytoken"}
        output = tmp_path / "gateway.yaml"
        generate_gateway_yaml(sample_mcps, output, remnux_config=remnux)
        config = yaml.safe_load(output.read_text())
        assert "remnux-mcp" in config["backends"]
        assert config["backends"]["remnux-mcp"]["type"] == "http"
        assert (
            "Bearer mytoken"
            in config["backends"]["remnux-mcp"]["headers"]["Authorization"]
        )

    def test_generate_gateway_yaml_api_keys(self, tmp_path, sample_mcps):
        keys = {"key1": {"analyst": "steve"}}
        output = tmp_path / "gateway.yaml"
        generate_gateway_yaml(sample_mcps, output, api_keys=keys)
        config = yaml.safe_load(output.read_text())
        assert config["api_keys"]["key1"]["analyst"] == "steve"


# -- Wizard tests --


class TestWizard:
    def test_wizard_clients_all(self):
        with patch("aiir_cli.setup.wizard._prompt", return_value="5"):
            result = wizard_clients()
        assert result == ["claude_code", "claude_desktop", "cursor", "openwebui"]

    def test_wizard_clients_single(self):
        with patch("aiir_cli.setup.wizard._prompt", return_value="2"):
            result = wizard_clients()
        assert result == ["claude_desktop"]

    def test_wizard_clients_cursor(self):
        with patch("aiir_cli.setup.wizard._prompt", return_value="3"):
            result = wizard_clients()
        assert result == ["cursor"]

    def test_wizard_clients_default(self):
        with patch("aiir_cli.setup.wizard._prompt", return_value=""):
            result = wizard_clients()
        assert result == ["claude_code"]


# -- cmd_setup integration --


class TestCmdSetup:
    def test_non_interactive_generates_mcp_json(self, tmp_path, identity):
        args = MagicMock()
        args.force_reprompt = False
        args.non_interactive = True
        args.setup_action = None

        fake_mcps = [
            {
                "name": "forensic-mcp",
                "module": "forensic_mcp",
                "python_path": "/usr/bin/python3",
                "available": True,
            },
        ]
        with (
            patch(
                "aiir_cli.commands.setup.detect_installed_mcps", return_value=fake_mcps
            ),
            patch("aiir_cli.commands.setup.detect_venv_mcps", return_value=[]),
            patch("aiir_cli.commands.setup.Path.cwd", return_value=tmp_path),
        ):
            cmd_setup(args, identity)

        output = tmp_path / ".mcp.json"
        assert output.exists()
        config = json.loads(output.read_text())
        assert "forensic-mcp" in config["mcpServers"]

    def test_setup_no_mcps_exits(self, identity):
        args = MagicMock()
        args.force_reprompt = False
        args.non_interactive = True
        args.setup_action = None

        with (
            patch("aiir_cli.commands.setup.detect_installed_mcps", return_value=[]),
            patch("aiir_cli.commands.setup.detect_venv_mcps", return_value=[]),
        ):
            with pytest.raises(SystemExit):
                cmd_setup(args, identity)

    def test_cursor_config_generation(self, tmp_path, sample_mcps):
        """Cursor uses same mcpServers format in .cursor/mcp.json."""
        output = tmp_path / ".cursor" / "mcp.json"
        generate_mcp_json(sample_mcps, output)
        assert output.exists()
        config = json.loads(output.read_text())
        assert "mcpServers" in config
        assert "forensic-mcp" in config["mcpServers"]

    def test_setup_test_runs(self, identity, capsys):
        args = MagicMock()
        args.setup_action = "test"

        with (
            patch("aiir_cli.commands.setup.detect_installed_mcps", return_value=[]),
            patch("aiir_cli.commands.setup.detect_venv_mcps", return_value=[]),
        ):
            cmd_setup(args, identity)

        output = capsys.readouterr().out
        assert "Connectivity Test" in output
        assert "No MCP servers detected" in output
