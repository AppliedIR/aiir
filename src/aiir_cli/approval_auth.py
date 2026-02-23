"""Approval authentication: mandatory PIN for approve/reject.

PIN uses getpass (reads from /dev/tty, no echo) to block
both AI-via-Bash AND expect-style terminal automation.
A PIN must be configured before approvals are allowed.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sys
import tempfile
import time
try:
    import termios
    import tty
    _HAS_TERMIOS = True
except ImportError:
    _HAS_TERMIOS = False
from pathlib import Path

import yaml


PBKDF2_ITERATIONS = 600_000
_MAX_PIN_ATTEMPTS = 3
_LOCKOUT_SECONDS = 900  # 15 minutes
_LOCKOUT_FILE = Path.home() / ".aiir" / ".pin_lockout"


def require_confirmation(config_path: Path, analyst: str) -> str:
    """Require PIN confirmation. Returns 'pin'.

    PIN must be configured for the analyst. If not, prints setup
    instructions and exits.

    Raises SystemExit on failure, lockout, or missing PIN.
    """
    if not has_pin(config_path, analyst):
        print(
            "No approval PIN configured. Set one with:\n"
            "  aiir config --setup-pin\n",
            file=sys.stderr,
        )
        sys.exit(1)
    _check_lockout(analyst)
    pin = _getpass_prompt("Enter PIN to confirm: ")
    if not verify_pin(config_path, analyst, pin):
        _record_failure(analyst)
        remaining = _MAX_PIN_ATTEMPTS - _recent_failure_count(analyst)
        if remaining <= 0:
            print(f"Too many failed attempts. Locked out for {_LOCKOUT_SECONDS}s.",
                  file=sys.stderr)
        else:
            print(f"Incorrect PIN. {remaining} attempt(s) remaining.",
                  file=sys.stderr)
        sys.exit(1)
    _clear_failures(analyst)
    return "pin"


def require_tty_confirmation(prompt: str) -> bool:
    """Prompt y/N via /dev/tty. Returns True if confirmed."""
    try:
        tty = open("/dev/tty", "r")
    except OSError:
        print("No terminal available (/dev/tty). Cannot confirm interactively.", file=sys.stderr)
        sys.exit(1)
    try:
        sys.stderr.write(prompt)
        sys.stderr.flush()
        response = tty.readline().strip().lower()
        return response == "y"
    finally:
        tty.close()


def has_pin(config_path: Path, analyst: str) -> bool:
    """Check if analyst has a PIN configured."""
    config = _load_config(config_path)
    pins = config.get("pins", {})
    return analyst in pins and "hash" in pins[analyst] and "salt" in pins[analyst]


def verify_pin(config_path: Path, analyst: str, pin: str) -> bool:
    """Verify a PIN against stored hash."""
    config = _load_config(config_path)
    pins = config.get("pins", {})
    entry = pins.get(analyst)
    if not entry:
        return False
    stored_hash = entry["hash"]
    salt = bytes.fromhex(entry["salt"])
    computed = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, PBKDF2_ITERATIONS).hex()
    return secrets.compare_digest(computed, stored_hash)


def setup_pin(config_path: Path, analyst: str) -> None:
    """Set up a new PIN for the analyst. Prompts twice to confirm."""
    pin1 = _getpass_prompt("Enter new PIN: ")
    if not pin1:
        print("PIN cannot be empty.", file=sys.stderr)
        sys.exit(1)
    pin2 = _getpass_prompt("Confirm new PIN: ")
    if pin1 != pin2:
        print("PINs do not match.", file=sys.stderr)
        sys.exit(1)

    salt = secrets.token_bytes(32)
    pin_hash = hashlib.pbkdf2_hmac("sha256", pin1.encode(), salt, PBKDF2_ITERATIONS).hex()

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config = _load_config(config_path)
    if "pins" not in config:
        config["pins"] = {}
    config["pins"][analyst] = {"hash": pin_hash, "salt": salt.hex()}

    _save_config(config_path, config)
    print(f"PIN configured for analyst '{analyst}'.")


def reset_pin(config_path: Path, analyst: str) -> None:
    """Reset PIN. Requires current PIN first."""
    if not has_pin(config_path, analyst):
        print(f"No PIN configured for analyst '{analyst}'. Use --setup-pin first.", file=sys.stderr)
        sys.exit(1)

    current = _getpass_prompt("Enter current PIN: ")
    if not verify_pin(config_path, analyst, current):
        print("Incorrect current PIN.", file=sys.stderr)
        sys.exit(1)

    setup_pin(config_path, analyst)


def _load_failures() -> dict[str, list[float]]:
    """Load failure timestamps from disk. Returns {} on missing/corrupt file."""
    try:
        data = json.loads(_LOCKOUT_FILE.read_text())
        if isinstance(data, dict):
            return data
    except (OSError, json.JSONDecodeError, ValueError):
        pass
    return {}


def _save_failures(data: dict[str, list[float]]) -> None:
    """Write failure timestamps to disk with 0o600 permissions."""
    _LOCKOUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(_LOCKOUT_FILE.parent), suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        os.replace(tmp_path, str(_LOCKOUT_FILE))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _recent_failure_count(analyst: str) -> int:
    """Count failures within the lockout window."""
    now = time.time()
    failures = _load_failures().get(analyst, [])
    return sum(1 for t in failures if now - t < _LOCKOUT_SECONDS)


def _check_lockout(analyst: str) -> None:
    """Exit if analyst is locked out from too many failed attempts."""
    if _recent_failure_count(analyst) >= _MAX_PIN_ATTEMPTS:
        now = time.time()
        failures = _load_failures().get(analyst, [])
        recent = [t for t in failures if now - t < _LOCKOUT_SECONDS]
        if recent:
            oldest_recent = min(recent)
            remaining = int(_LOCKOUT_SECONDS - (now - oldest_recent))
            remaining = max(remaining, 1)
        else:
            remaining = _LOCKOUT_SECONDS
        print(f"PIN locked. Too many failed attempts. Try again in {remaining} seconds.", file=sys.stderr)
        sys.exit(1)


def _record_failure(analyst: str) -> None:
    """Record a failed PIN attempt to disk."""
    data = _load_failures()
    data.setdefault(analyst, []).append(time.time())
    _save_failures(data)


def _clear_failures(analyst: str) -> None:
    """Clear failures on successful authentication."""
    data = _load_failures()
    if analyst in data:
        del data[analyst]
        _save_failures(data)


def _getpass_prompt(prompt: str) -> str:
    """Read PIN from /dev/tty with masked input (shows * per keystroke).

    On Windows (no termios), falls back to getpass.getpass().
    """
    if not _HAS_TERMIOS:
        import getpass
        return getpass.getpass(prompt)

    try:
        tty_in = open("/dev/tty", "r")
    except OSError:
        import getpass
        return getpass.getpass(prompt)
    try:
        fd = tty_in.fileno()
        sys.stderr.write(prompt)
        sys.stderr.flush()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            pin = []
            while True:
                ch = os.read(fd, 1).decode("utf-8", errors="replace")
                if ch in ("\r", "\n"):
                    break
                elif ch in ("\x7f", "\x08"):  # backspace/delete
                    if pin:
                        pin.pop()
                        sys.stderr.write("\b \b")
                        sys.stderr.flush()
                elif ch == "\x03":  # Ctrl-C
                    sys.stderr.write("\n")
                    sys.stderr.flush()
                    raise KeyboardInterrupt
                elif ch >= " ":  # printable
                    pin.append(ch)
                    sys.stderr.write("*")
                    sys.stderr.flush()
            return "".join(pin)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            sys.stderr.write("\n")
            sys.stderr.flush()
    finally:
        tty_in.close()


def _load_config(config_path: Path) -> dict:
    """Load YAML config file."""
    if not config_path.exists():
        return {}
    with open(config_path) as f:
        return yaml.safe_load(f) or {}


def _save_config(config_path: Path, config: dict) -> None:
    """Save YAML config file atomically with restricted permissions."""
    config_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(config_path.parent), suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            yaml.dump(config, f, default_flow_style=False)
        os.replace(tmp_path, str(config_path))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
