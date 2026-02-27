"""Tests for approval authentication module."""

import json
from unittest.mock import MagicMock, patch

import pytest
import yaml

from aiir_cli.approval_auth import (
    _LOCKOUT_SECONDS,
    _MAX_PIN_ATTEMPTS,
    _check_lockout,
    _clear_failures,
    _recent_failure_count,
    _record_failure,
    has_pin,
    require_confirmation,
    require_tty_confirmation,
    reset_pin,
    setup_pin,
    verify_pin,
)


@pytest.fixture
def config_path(tmp_path):
    """Config file path in a temp directory."""
    return tmp_path / ".aiir" / "config.yaml"


class TestPinSetup:
    def test_setup_pin_creates_config(self, config_path):
        with patch(
            "aiir_cli.approval_auth.getpass_prompt", side_effect=["1234", "1234"]
        ):
            setup_pin(config_path, "steve")
        assert config_path.exists()
        config = yaml.safe_load(config_path.read_text())
        assert "steve" in config["pins"]
        assert "hash" in config["pins"]["steve"]
        assert "salt" in config["pins"]["steve"]

    def test_setup_pin_verify_roundtrip(self, config_path):
        with patch(
            "aiir_cli.approval_auth.getpass_prompt", side_effect=["mypin", "mypin"]
        ):
            setup_pin(config_path, "analyst1")
        assert verify_pin(config_path, "analyst1", "mypin")

    def test_wrong_pin_fails(self, config_path):
        with patch(
            "aiir_cli.approval_auth.getpass_prompt", side_effect=["correct", "correct"]
        ):
            setup_pin(config_path, "analyst1")
        assert not verify_pin(config_path, "analyst1", "wrong")

    def test_has_pin_false_when_no_config(self, config_path):
        assert not has_pin(config_path, "analyst1")

    def test_has_pin_true_after_setup(self, config_path):
        with patch(
            "aiir_cli.approval_auth.getpass_prompt", side_effect=["1234", "1234"]
        ):
            setup_pin(config_path, "analyst1")
        assert has_pin(config_path, "analyst1")

    def test_setup_pin_mismatch_exits(self, config_path):
        with patch(
            "aiir_cli.approval_auth.getpass_prompt", side_effect=["pin1", "pin2"]
        ):
            with pytest.raises(SystemExit):
                setup_pin(config_path, "analyst1")

    def test_setup_pin_empty_exits(self, config_path):
        with patch("aiir_cli.approval_auth.getpass_prompt", side_effect=["", ""]):
            with pytest.raises(SystemExit):
                setup_pin(config_path, "analyst1")

    def test_setup_pin_preserves_existing_config(self, config_path):
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            yaml.dump({"analyst": "steve"}, f)
        with patch(
            "aiir_cli.approval_auth.getpass_prompt", side_effect=["1234", "1234"]
        ):
            setup_pin(config_path, "steve")
        config = yaml.safe_load(config_path.read_text())
        assert config["analyst"] == "steve"
        assert "steve" in config["pins"]


class TestPinReset:
    def test_reset_pin_requires_current(self, config_path):
        with patch("aiir_cli.approval_auth.getpass_prompt", side_effect=["old", "old"]):
            setup_pin(config_path, "analyst1")
        # Wrong current PIN
        with patch("aiir_cli.approval_auth.getpass_prompt", side_effect=["wrong"]):
            with pytest.raises(SystemExit):
                reset_pin(config_path, "analyst1")

    def test_reset_pin_success(self, config_path):
        with patch("aiir_cli.approval_auth.getpass_prompt", side_effect=["old", "old"]):
            setup_pin(config_path, "analyst1")
        # Correct current, then new PIN twice
        with patch(
            "aiir_cli.approval_auth.getpass_prompt", side_effect=["old", "new", "new"]
        ):
            reset_pin(config_path, "analyst1")
        assert verify_pin(config_path, "analyst1", "new")
        assert not verify_pin(config_path, "analyst1", "old")

    def test_reset_no_pin_exits(self, config_path):
        with pytest.raises(SystemExit):
            reset_pin(config_path, "analyst1")


class TestRequireConfirmation:
    def test_pin_mode_correct(self, config_path):
        with patch(
            "aiir_cli.approval_auth.getpass_prompt", side_effect=["1234", "1234"]
        ):
            setup_pin(config_path, "analyst1")
        with patch("aiir_cli.approval_auth.getpass_prompt", return_value="1234"):
            mode, pin = require_confirmation(config_path, "analyst1")
        assert mode == "pin"
        assert pin == "1234"

    def test_pin_mode_wrong_exits(self, config_path):
        with patch(
            "aiir_cli.approval_auth.getpass_prompt", side_effect=["1234", "1234"]
        ):
            setup_pin(config_path, "analyst1")
        with patch("aiir_cli.approval_auth.getpass_prompt", return_value="wrong"):
            with pytest.raises(SystemExit):
                require_confirmation(config_path, "analyst1")

    def test_no_pin_configured_exits(self, config_path, capsys):
        """require_confirmation with no PIN configured exits with setup instructions."""
        with pytest.raises(SystemExit):
            require_confirmation(config_path, "analyst1")
        captured = capsys.readouterr()
        assert "No approval PIN configured" in captured.err
        assert "aiir config --setup-pin" in captured.err


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


@pytest.fixture(autouse=True)
def isolate_lockout_file(tmp_path, monkeypatch):
    """Point lockout file to temp dir and clean between tests."""
    lockout = tmp_path / ".pin_lockout"
    monkeypatch.setattr("aiir_cli.approval_auth._LOCKOUT_FILE", lockout)
    yield lockout
    if lockout.exists():
        lockout.unlink()


class TestPinLockout:
    def test_three_failures_triggers_lockout(self, capsys):
        """3 failed PIN attempts triggers lockout."""
        for _ in range(_MAX_PIN_ATTEMPTS):
            _record_failure("analyst1")
        with pytest.raises(SystemExit):
            _check_lockout("analyst1")
        captured = capsys.readouterr()
        assert "PIN locked" in captured.err
        assert "seconds" in captured.err

    def test_lockout_expires_after_timeout(self, monkeypatch):
        """Lockout expires after _LOCKOUT_SECONDS."""
        import time as time_mod

        base_time = 1000000.0
        call_count = [0]

        def mock_time():
            call_count[0] += 1
            # First 3 calls are for _record_failure (recording timestamps)
            if call_count[0] <= _MAX_PIN_ATTEMPTS:
                return base_time
            # Subsequent calls are after lockout has expired
            return base_time + _LOCKOUT_SECONDS + 1

        monkeypatch.setattr(time_mod, "time", mock_time)
        for _ in range(_MAX_PIN_ATTEMPTS):
            _record_failure("analyst1")
        # After lockout expires, check should NOT raise
        _check_lockout("analyst1")

    def test_successful_auth_clears_failure_count(self, config_path):
        """Successful authentication clears failure count."""
        _record_failure("analyst1")
        _record_failure("analyst1")
        assert _recent_failure_count("analyst1") == 2
        _clear_failures("analyst1")
        assert _recent_failure_count("analyst1") == 0

    def test_failures_do_not_cross_contaminate(self):
        """Failures from different analysts do not cross-contaminate."""
        for _ in range(_MAX_PIN_ATTEMPTS):
            _record_failure("analyst1")
        # analyst2 should not be locked out
        _check_lockout("analyst2")  # Should not raise
        assert _recent_failure_count("analyst2") == 0

    def test_under_threshold_no_lockout(self):
        """Fewer than _MAX_PIN_ATTEMPTS failures does not trigger lockout."""
        for _ in range(_MAX_PIN_ATTEMPTS - 1):
            _record_failure("analyst1")
        _check_lockout("analyst1")  # Should not raise

    def test_require_confirmation_records_failure_on_wrong_pin(self, config_path):
        """require_confirmation records failure on wrong PIN."""
        with patch(
            "aiir_cli.approval_auth.getpass_prompt", side_effect=["1234", "1234"]
        ):
            setup_pin(config_path, "analyst1")
        with patch("aiir_cli.approval_auth.getpass_prompt", return_value="wrong"):
            with pytest.raises(SystemExit):
                require_confirmation(config_path, "analyst1")
        assert _recent_failure_count("analyst1") == 1

    def test_require_confirmation_clears_on_success(self, config_path):
        """require_confirmation clears failures on correct PIN."""
        with patch(
            "aiir_cli.approval_auth.getpass_prompt", side_effect=["1234", "1234"]
        ):
            setup_pin(config_path, "analyst1")
        _record_failure("analyst1")
        assert _recent_failure_count("analyst1") == 1
        with patch("aiir_cli.approval_auth.getpass_prompt", return_value="1234"):
            mode, pin = require_confirmation(config_path, "analyst1")
        assert mode == "pin"
        assert pin == "1234"
        assert _recent_failure_count("analyst1") == 0

    def test_lockout_blocks_require_confirmation(self, config_path):
        """Locked-out analyst cannot even attempt PIN entry."""
        with patch(
            "aiir_cli.approval_auth.getpass_prompt", side_effect=["1234", "1234"]
        ):
            setup_pin(config_path, "analyst1")
        for _ in range(_MAX_PIN_ATTEMPTS):
            _record_failure("analyst1")
        with pytest.raises(SystemExit):
            require_confirmation(config_path, "analyst1")

    def test_lockout_persists_across_clear(self, isolate_lockout_file):
        """Lockout file survives even if in-process state is gone."""
        for _ in range(_MAX_PIN_ATTEMPTS):
            _record_failure("analyst1")
        # Verify lockout file exists and has data
        assert isolate_lockout_file.exists()
        data = json.loads(isolate_lockout_file.read_text())
        assert len(data["analyst1"]) == _MAX_PIN_ATTEMPTS
        # Simulating process restart: re-read from disk
        assert _recent_failure_count("analyst1") == _MAX_PIN_ATTEMPTS

    def test_lockout_file_corrupt_treated_as_empty(self, isolate_lockout_file):
        """Corrupt lockout file is treated as empty (zero failures)."""
        isolate_lockout_file.parent.mkdir(parents=True, exist_ok=True)
        isolate_lockout_file.write_text("not valid json {{{")
        assert _recent_failure_count("analyst1") == 0

    def test_lockout_file_permissions(self, isolate_lockout_file):
        """Lockout file has 0o600 permissions."""
        _record_failure("analyst1")
        assert isolate_lockout_file.exists()
        assert (isolate_lockout_file.stat().st_mode & 0o777) == 0o600


class TestPinConfigFilePermissions:
    def test_pin_config_file_permissions(self, config_path):
        """After setup_pin, config file has permissions 0o600."""
        with patch(
            "aiir_cli.approval_auth.getpass_prompt", side_effect=["1234", "1234"]
        ):
            setup_pin(config_path, "steve")
        assert config_path.exists()
        assert (config_path.stat().st_mode & 0o777) == 0o600
