"""Tests for approval authentication module."""

import os
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
import yaml

from air_cli.approval_auth import (
    has_pin,
    setup_pin,
    verify_pin,
    reset_pin,
    require_confirmation,
    require_tty_confirmation,
)


@pytest.fixture
def config_path(tmp_path):
    """Config file path in a temp directory."""
    return tmp_path / ".air" / "config.yaml"


class TestPinSetup:
    def test_setup_pin_creates_config(self, config_path):
        with patch("air_cli.approval_auth._getpass_prompt", side_effect=["1234", "1234"]):
            setup_pin(config_path, "steve")
        assert config_path.exists()
        config = yaml.safe_load(config_path.read_text())
        assert "steve" in config["pins"]
        assert "hash" in config["pins"]["steve"]
        assert "salt" in config["pins"]["steve"]

    def test_setup_pin_verify_roundtrip(self, config_path):
        with patch("air_cli.approval_auth._getpass_prompt", side_effect=["mypin", "mypin"]):
            setup_pin(config_path, "analyst1")
        assert verify_pin(config_path, "analyst1", "mypin")

    def test_wrong_pin_fails(self, config_path):
        with patch("air_cli.approval_auth._getpass_prompt", side_effect=["correct", "correct"]):
            setup_pin(config_path, "analyst1")
        assert not verify_pin(config_path, "analyst1", "wrong")

    def test_has_pin_false_when_no_config(self, config_path):
        assert not has_pin(config_path, "analyst1")

    def test_has_pin_true_after_setup(self, config_path):
        with patch("air_cli.approval_auth._getpass_prompt", side_effect=["1234", "1234"]):
            setup_pin(config_path, "analyst1")
        assert has_pin(config_path, "analyst1")

    def test_setup_pin_mismatch_exits(self, config_path):
        with patch("air_cli.approval_auth._getpass_prompt", side_effect=["pin1", "pin2"]):
            with pytest.raises(SystemExit):
                setup_pin(config_path, "analyst1")

    def test_setup_pin_empty_exits(self, config_path):
        with patch("air_cli.approval_auth._getpass_prompt", side_effect=["", ""]):
            with pytest.raises(SystemExit):
                setup_pin(config_path, "analyst1")

    def test_setup_pin_preserves_existing_config(self, config_path):
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            yaml.dump({"analyst": "steve"}, f)
        with patch("air_cli.approval_auth._getpass_prompt", side_effect=["1234", "1234"]):
            setup_pin(config_path, "steve")
        config = yaml.safe_load(config_path.read_text())
        assert config["analyst"] == "steve"
        assert "steve" in config["pins"]


class TestPinReset:
    def test_reset_pin_requires_current(self, config_path):
        with patch("air_cli.approval_auth._getpass_prompt", side_effect=["old", "old"]):
            setup_pin(config_path, "analyst1")
        # Wrong current PIN
        with patch("air_cli.approval_auth._getpass_prompt", side_effect=["wrong"]):
            with pytest.raises(SystemExit):
                reset_pin(config_path, "analyst1")

    def test_reset_pin_success(self, config_path):
        with patch("air_cli.approval_auth._getpass_prompt", side_effect=["old", "old"]):
            setup_pin(config_path, "analyst1")
        # Correct current, then new PIN twice
        with patch("air_cli.approval_auth._getpass_prompt", side_effect=["old", "new", "new"]):
            reset_pin(config_path, "analyst1")
        assert verify_pin(config_path, "analyst1", "new")
        assert not verify_pin(config_path, "analyst1", "old")

    def test_reset_no_pin_exits(self, config_path):
        with pytest.raises(SystemExit):
            reset_pin(config_path, "analyst1")


class TestRequireConfirmation:
    def test_pin_mode_correct(self, config_path):
        with patch("air_cli.approval_auth._getpass_prompt", side_effect=["1234", "1234"]):
            setup_pin(config_path, "analyst1")
        with patch("air_cli.approval_auth._getpass_prompt", return_value="1234"):
            mode = require_confirmation(config_path, "analyst1")
        assert mode == "pin"

    def test_pin_mode_wrong_exits(self, config_path):
        with patch("air_cli.approval_auth._getpass_prompt", side_effect=["1234", "1234"]):
            setup_pin(config_path, "analyst1")
        with patch("air_cli.approval_auth._getpass_prompt", return_value="wrong"):
            with pytest.raises(SystemExit):
                require_confirmation(config_path, "analyst1")

    def test_interactive_mode_confirmed(self, config_path):
        mock_tty = MagicMock()
        mock_tty.readline.return_value = "y\n"
        with patch("builtins.open", return_value=mock_tty):
            mode = require_confirmation(config_path, "analyst1")
        assert mode == "interactive"

    def test_interactive_mode_cancelled(self, config_path):
        mock_tty = MagicMock()
        mock_tty.readline.return_value = "n\n"
        with patch("builtins.open", return_value=mock_tty):
            with pytest.raises(SystemExit):
                require_confirmation(config_path, "analyst1")


class TestTtyConfirmation:
    def test_tty_y_returns_true(self):
        mock_tty = MagicMock()
        mock_tty.readline.return_value = "y\n"
        with patch("builtins.open", return_value=mock_tty):
            assert require_tty_confirmation("Confirm? ") is True

    def test_tty_n_returns_false(self):
        mock_tty = MagicMock()
        mock_tty.readline.return_value = "n\n"
        with patch("builtins.open", return_value=mock_tty):
            assert require_tty_confirmation("Confirm? ") is False

    def test_tty_empty_returns_false(self):
        mock_tty = MagicMock()
        mock_tty.readline.return_value = "\n"
        with patch("builtins.open", return_value=mock_tty):
            assert require_tty_confirmation("Confirm? ") is False

    def test_no_tty_exits(self):
        with patch("builtins.open", side_effect=OSError("No tty")):
            with pytest.raises(SystemExit):
                require_tty_confirmation("Confirm? ")
