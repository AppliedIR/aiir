"""Approval authentication: /dev/tty confirmation and optional PIN.

/dev/tty is the controlling terminal — separate from stdin.
AI running `air approve` through Bash cannot answer it.

Optional PIN uses getpass (reads from /dev/tty, no echo) to block
both AI-via-Bash AND expect-style terminal automation.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import sys
import tempfile
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
_LOCKOUT_SECONDS = 60
_pin_failures: dict[str, list[float]] = {}  # analyst -> list of failure timestamps


def require_confirmation(config_path: Path, analyst: str) -> str:
    """Require human confirmation. Returns mode used: 'pin' or 'interactive'.

    If PIN is configured for analyst, prompts for PIN via getpass.
    Otherwise, prompts y/N via /dev/tty.

    Raises SystemExit on failure or cancellation.
    """
    if has_pin(config_path, analyst):
        _check_lockout(analyst)
        pin = _getpass_prompt("Enter PIN to confirm: ")
        if not verify_pin(config_path, analyst, pin):
            _record_failure(analyst)
            remaining = _MAX_PIN_ATTEMPTS - _recent_failure_count(analyst)
            if remaining <= 0:
                print(f"Too many failed attempts. Locked out for {_LOCKOUT_SECONDS}s.", file=sys.stderr)
            else:
                print(f"Incorrect PIN. {remaining} attempt(s) remaining.", file=sys.stderr)
            sys.exit(1)
        _clear_failures(analyst)
        return "pin"
    else:
        if not require_tty_confirmation("Confirm? [y/N]: "):
            print("Cancelled.", file=sys.stderr)
            sys.exit(1)
        return "interactive"


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


def _recent_failure_count(analyst: str) -> int:
    """Count failures within the lockout window."""
    import time
    now = time.monotonic()
    failures = _pin_failures.get(analyst, [])
    return sum(1 for t in failures if now - t < _LOCKOUT_SECONDS)


def _check_lockout(analyst: str) -> None:
    """Exit if analyst is locked out from too many failed attempts."""
    if _recent_failure_count(analyst) >= _MAX_PIN_ATTEMPTS:
        import time
        failures = _pin_failures.get(analyst, [])
        if failures:
            oldest_recent = min(t for t in failures if time.monotonic() - t < _LOCKOUT_SECONDS)
            remaining = int(_LOCKOUT_SECONDS - (time.monotonic() - oldest_recent))
            remaining = max(remaining, 1)
        else:
            remaining = _LOCKOUT_SECONDS
        print(f"PIN locked. Too many failed attempts. Try again in {remaining} seconds.", file=sys.stderr)
        sys.exit(1)


def _record_failure(analyst: str) -> None:
    """Record a failed PIN attempt."""
    import time
    _pin_failures.setdefault(analyst, []).append(time.monotonic())


def _clear_failures(analyst: str) -> None:
    """Clear failures on successful authentication."""
    _pin_failures.pop(analyst, None)


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
