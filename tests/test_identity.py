"""Tests for analyst identity resolution."""

import os
from unittest.mock import patch

from air_cli.identity import get_analyst_identity


def test_flag_override_takes_priority():
    identity = get_analyst_identity(flag_override="analyst1")
    assert identity["analyst"] == "analyst1"
    assert identity["analyst_source"] == "flag"
    assert "os_user" in identity


def test_env_var_second_priority():
    with patch.dict(os.environ, {"AIR_ANALYST": "env_analyst"}):
        identity = get_analyst_identity()
        assert identity["analyst"] == "env_analyst"
        assert identity["analyst_source"] == "env"


def test_os_user_fallback():
    with patch.dict(os.environ, {}, clear=False):
        # Remove AIR_ANALYST if present
        os.environ.pop("AIR_ANALYST", None)
        identity = get_analyst_identity()
        assert identity["analyst_source"] == "os_user" or identity["analyst_source"] == "config"
        assert identity["os_user"] == os.environ.get("USER", os.environ.get("USERNAME", "unknown"))
