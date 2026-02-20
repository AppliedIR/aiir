"""Tests for air config command."""

from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from air_cli.commands.config import cmd_config


@pytest.fixture
def config_dir(tmp_path):
    """Use tmp_path as home for config."""
    return tmp_path


@pytest.fixture
def identity():
    return {"os_user": "testuser", "analyst": "analyst1", "analyst_source": "flag"}


class FakeArgs:
    def __init__(self, analyst=None, show=False, setup_pin=False, reset_pin=False):
        self.analyst = analyst
        self.show = show
        self.setup_pin = setup_pin
        self.reset_pin = reset_pin


class TestConfig:
    def test_set_analyst(self, config_dir, identity):
        config_path = config_dir / ".air" / "config.yaml"
        args = FakeArgs(analyst="new_analyst")
        with patch("air_cli.commands.config.Path.home", return_value=config_dir):
            cmd_config(args, identity)
        config = yaml.safe_load(config_path.read_text())
        assert config["analyst"] == "new_analyst"

    def test_show_config(self, config_dir, identity, capsys):
        config_path = config_dir / ".air" / "config.yaml"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(yaml.dump({"analyst": "test_analyst"}))
        args = FakeArgs(show=True)
        with patch("air_cli.commands.config.Path.home", return_value=config_dir):
            cmd_config(args, identity)
        out = capsys.readouterr().out
        assert "test_analyst" in out

    def test_show_when_no_config_file(self, config_dir, identity, capsys):
        args = FakeArgs(show=True)
        with patch("air_cli.commands.config.Path.home", return_value=config_dir):
            cmd_config(args, identity)
        out = capsys.readouterr().out
        assert "No configuration file found" in out
