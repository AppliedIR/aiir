#!/usr/bin/env bash
#
# setup-aiir.sh -- AIIR CLI Installer
#
# Standalone installer for the aiir CLI, the human interface for the AIIR
# platform. Handles approval workflows, evidence management, and forensic
# command execution. Only dependency is pyyaml.
#
# Works on Linux (SIFT, Ubuntu, Debian, RHEL) and macOS.
# Windows users: install via `pip install -e .` directly.
#
# Usage:
#   ./setup-aiir.sh                              # Interactive
#   ./setup-aiir.sh -y --examiner=steve          # Fully unattended
#   ./setup-aiir.sh --venv=/path/to/venv         # Use existing venv
#   ./setup-aiir.sh --install-dir=~/tools/aiir   # Custom location
#
set -euo pipefail

# =============================================================================
# Parse Arguments
# =============================================================================

AUTO_YES=false
INSTALL_DIR_ARG=""
VENV_ARG=""
EXAMINER_ARG=""

for arg in "$@"; do
    case "$arg" in
        -y|--yes)          AUTO_YES=true ;;
        --install-dir=*)   INSTALL_DIR_ARG="${arg#*=}" ;;
        --venv=*)          VENV_ARG="${arg#*=}" ;;
        --examiner=*)      EXAMINER_ARG="${arg#*=}" ;;
        -h|--help)
            echo "Usage: setup-aiir.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -y, --yes            Accept all defaults (unattended)"
            echo "  --install-dir=PATH   Where to clone (default: ~/aiir/aiir-cli)"
            echo "  --venv=PATH          Use existing venv (for integration with sift-mcp installer)"
            echo "  --examiner=NAME      Examiner identity slug"
            echo "  -h, --help           Show this help"
            echo ""
            echo "Requirements: Python 3.10+ and pyyaml (only dependency)."
            echo "Works on Linux and macOS. Windows users: install via pip directly."
            exit 0
            ;;
        *)
            echo "Unknown option: $arg (use -h for help)"
            exit 1
            ;;
    esac
done

# =============================================================================
# Colors and Helpers
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

info()   { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()     { echo -e "${GREEN}[OK]${NC} $*"; }
warn()   { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()    { echo -e "${RED}[ERROR]${NC} $*"; }
header() { echo -e "\n${BOLD}=== $* ===${NC}\n"; }

prompt() {
    local msg="$1" default="${2:-}"
    if $AUTO_YES && [[ -n "$default" ]]; then
        echo "$default"
        return
    fi
    if [[ -n "$default" ]]; then
        read -rp "$(echo -e "${BOLD}$msg${NC} [$default]: ")" answer
        echo "${answer:-$default}"
    else
        read -rp "$(echo -e "${BOLD}$msg${NC}: ")" answer
        echo "$answer"
    fi
}

# Portable resolve_path (works on macOS where resolve_path is unavailable)
resolve_path() {
    local target="$1"
    # If the directory exists, resolve directly
    if [[ -d "$target" ]]; then
        (cd "$target" && pwd)
    else
        # Ensure parent exists, then resolve
        local parent
        parent="$(dirname "$target")"
        mkdir -p "$parent" 2>/dev/null || true
        if [[ -d "$parent" ]]; then
            echo "$(cd "$parent" && pwd)/$(basename "$target")"
        else
            echo "$target"
        fi
    fi
}

# =============================================================================
# Banner
# =============================================================================

echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}  AIIR CLI Installer${NC}"
echo -e "${BOLD}  Artificial Intelligence Incident Response -- Human Interface${NC}"
echo -e "${BOLD}============================================================${NC}"
echo ""

# =============================================================================
# Phase 1: Prerequisites
# =============================================================================

header "Phase 1: Prerequisites"

# Python 3.10+
if command -v python3 &>/dev/null; then
    PYTHON=$(command -v python3)
    PY_VERSION=$($PYTHON -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PY_MAJOR=$($PYTHON -c 'import sys; print(sys.version_info.major)')
    PY_MINOR=$($PYTHON -c 'import sys; print(sys.version_info.minor)')
    if (( PY_MAJOR >= 3 && PY_MINOR >= 10 )); then
        ok "Python $PY_VERSION ($PYTHON)"
    else
        err "Python 3.10+ required (found $PY_VERSION)"
        if [[ "$(uname)" == "Darwin" ]]; then
            echo "  Install: brew install python@3.12"
        else
            echo "  Install: sudo apt install python3.10 python3.10-venv"
        fi
        exit 1
    fi
else
    err "Python 3 not found"
    if [[ "$(uname)" == "Darwin" ]]; then
        echo "  Install: brew install python@3.12"
    else
        echo "  Install: sudo apt install python3 python3-venv"
    fi
    exit 1
fi

# pip
if $PYTHON -m pip --version &>/dev/null; then
    ok "pip available"
else
    err "pip not found"
    if [[ "$(uname)" == "Darwin" ]]; then
        echo "  pip is included with Homebrew Python. Try: brew install python@3.12"
    else
        echo "  Install: sudo apt install python3-pip"
    fi
    exit 1
fi

# venv (only needed if not using --venv)
if [[ -z "$VENV_ARG" ]]; then
    if $PYTHON -m venv --help &>/dev/null 2>&1; then
        ok "venv available"
    else
        err "python3-venv not found"
        if [[ "$(uname)" == "Darwin" ]]; then
            echo "  venv is included with Homebrew Python. Try: brew install python@3.12"
        else
            echo "  Install: sudo apt install python3-venv"
        fi
        exit 1
    fi
fi

# git
if command -v git &>/dev/null; then
    ok "git $(git --version | awk '{print $3}')"
else
    err "git not found"
    if [[ "$(uname)" == "Darwin" ]]; then
        echo "  Install: xcode-select --install  (or: brew install git)"
    else
        echo "  Install: sudo apt install git"
    fi
    exit 1
fi

# Network (test with a public endpoint -- AppliedIR repos may be private)
if curl -sf --max-time 10 "https://github.com" &>/dev/null; then
    ok "Network access to GitHub"
elif git ls-remote https://github.com/AppliedIR/aiir.git HEAD &>/dev/null 2>&1; then
    ok "Network access to GitHub"
else
    warn "Cannot reach GitHub -- installation requires network access"
    exit 1
fi

# =============================================================================
# Phase 2: Clone and Install
# =============================================================================

header "Phase 2: Clone and Install"

# Determine install directory
if [[ -n "$INSTALL_DIR_ARG" ]]; then
    INSTALL_DIR="$INSTALL_DIR_ARG"
else
    INSTALL_DIR=$(prompt "Installation directory" "$HOME/aiir/aiir-cli")
fi
INSTALL_DIR=$(resolve_path "$INSTALL_DIR")

# Clone or update
if [[ -d "$INSTALL_DIR/.git" ]]; then
    info "Existing repo found. Pulling latest..."
    (cd "$INSTALL_DIR" && git pull --quiet) || warn "Could not update -- continuing with existing code"
    ok "Updated: $INSTALL_DIR"
elif [[ -d "$INSTALL_DIR" ]] && [[ "$(ls -A "$INSTALL_DIR" 2>/dev/null)" ]]; then
    err "Directory $INSTALL_DIR exists and is not a git repo"
    echo "  Remove it or choose a different --install-dir"
    exit 1
else
    info "Cloning aiir..."
    mkdir -p "$(dirname "$INSTALL_DIR")"
    git clone --quiet https://github.com/AppliedIR/aiir.git "$INSTALL_DIR"
    ok "Cloned to $INSTALL_DIR"
fi

# Set up venv
if [[ -n "$VENV_ARG" ]]; then
    VENV_DIR=$(resolve_path "$VENV_ARG")
    if [[ ! -d "$VENV_DIR" ]]; then
        err "Specified venv does not exist: $VENV_DIR"
        exit 1
    fi
    if [[ ! -f "$VENV_DIR/bin/python" ]] && [[ ! -f "$VENV_DIR/bin/python3" ]]; then
        err "No Python found in venv: $VENV_DIR"
        exit 1
    fi
    ok "Using existing venv: $VENV_DIR"
else
    VENV_DIR="$INSTALL_DIR/.venv"
    if [[ ! -d "$VENV_DIR" ]]; then
        info "Creating virtual environment..."
        $PYTHON -m venv "$VENV_DIR"
    fi
    "$VENV_DIR/bin/pip" install --progress-bar off --upgrade pip >/dev/null 2>&1
    ok "Virtual environment: $VENV_DIR"
fi

VENV_PYTHON="$VENV_DIR/bin/python"

# Install aiir CLI
info "Installing aiir CLI (pip install -e .)..."
"$VENV_DIR/bin/pip" install --progress-bar off -e "$INSTALL_DIR"
ok "aiir CLI installed"

# Verify import
if "$VENV_PYTHON" -c "import aiir_cli" 2>/dev/null; then
    ok "aiir_cli importable"
else
    err "aiir_cli import failed -- installation may be broken"
    exit 1
fi

# Add venv bin to PATH
AIIR_BIN="$VENV_DIR/bin"
if [[ ":$PATH:" != *":$AIIR_BIN:"* ]]; then
    SHELL_RC=""
    if [[ -f "$HOME/.zshrc" ]] && [[ "$(basename "$SHELL" 2>/dev/null)" == "zsh" ]]; then
        SHELL_RC="$HOME/.zshrc"
    elif [[ -f "$HOME/.bashrc" ]]; then
        SHELL_RC="$HOME/.bashrc"
    elif [[ -f "$HOME/.zshrc" ]]; then
        SHELL_RC="$HOME/.zshrc"
    fi

    if [[ -n "$SHELL_RC" ]]; then
        # Check if we already added a PATH entry for this venv
        if ! grep -qF "$AIIR_BIN" "$SHELL_RC" 2>/dev/null; then
            echo "" >> "$SHELL_RC"
            echo "# AIIR CLI" >> "$SHELL_RC"
            echo "export PATH=\"$AIIR_BIN:\$PATH\"" >> "$SHELL_RC"
            ok "Added aiir to PATH in $SHELL_RC"
        else
            ok "PATH already configured in $SHELL_RC"
        fi
    else
        warn "No shell config found. Add this to your shell profile:"
        echo "  export PATH=\"$AIIR_BIN:\$PATH\""
    fi
    export PATH="$AIIR_BIN:$PATH"
fi

# =============================================================================
# Phase 3: Examiner Identity
# =============================================================================

header "Phase 3: Examiner Identity"

echo "Your examiner name identifies your work in case files and audit trails."
echo "Use a short slug (e.g., steve, jane, analyst1)."
echo ""

if [[ -n "$EXAMINER_ARG" ]]; then
    EXAMINER="$EXAMINER_ARG"
else
    EXAMINER=$(prompt "Examiner name" "$(whoami)")
fi
EXAMINER=$(echo "$EXAMINER" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9-')

if [[ -z "$EXAMINER" ]]; then
    EXAMINER=$(whoami | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9-')
fi
if [[ -z "$EXAMINER" ]]; then
    EXAMINER="examiner"
fi

# Save to config
mkdir -p "$HOME/.aiir"

# Preserve existing config entries if config.yaml already exists
if [[ -f "$HOME/.aiir/config.yaml" ]]; then
    # Update or add examiner line
    if grep -q "^examiner:" "$HOME/.aiir/config.yaml" 2>/dev/null; then
        sed -i.bak "s/^examiner:.*$/examiner: $EXAMINER/" "$HOME/.aiir/config.yaml"
        rm -f "$HOME/.aiir/config.yaml.bak"
    else
        echo "examiner: $EXAMINER" >> "$HOME/.aiir/config.yaml"
    fi
else
    cat > "$HOME/.aiir/config.yaml" << EOF
examiner: $EXAMINER
EOF
fi
ok "Saved examiner identity: $EXAMINER"

# Add AIIR_EXAMINER to shell profile
SHELL_RC=""
if [[ -f "$HOME/.zshrc" ]] && [[ "$(basename "$SHELL" 2>/dev/null)" == "zsh" ]]; then
    SHELL_RC="$HOME/.zshrc"
elif [[ -f "$HOME/.bashrc" ]]; then
    SHELL_RC="$HOME/.bashrc"
elif [[ -f "$HOME/.zshrc" ]]; then
    SHELL_RC="$HOME/.zshrc"
fi

if [[ -n "$SHELL_RC" ]]; then
    if grep -q "AIIR_EXAMINER" "$SHELL_RC" 2>/dev/null; then
        sed -i.bak "s/^export AIIR_EXAMINER=.*$/export AIIR_EXAMINER=\"$EXAMINER\"/" "$SHELL_RC"
        rm -f "$SHELL_RC.bak"
        ok "Updated AIIR_EXAMINER in $SHELL_RC"
    else
        echo "export AIIR_EXAMINER=\"$EXAMINER\"" >> "$SHELL_RC"
        ok "Added AIIR_EXAMINER to $SHELL_RC"
    fi
fi
export AIIR_EXAMINER="$EXAMINER"

# =============================================================================
# Phase 4: Verification and Summary
# =============================================================================

header "Phase 4: Verification"

VERIFY_OK=true

# Test aiir --help
if "$VENV_DIR/bin/aiir" --help &>/dev/null; then
    ok "aiir --help works"
else
    warn "aiir --help failed"
    VERIFY_OK=false
fi

# Test examiner config
if [[ -f "$HOME/.aiir/config.yaml" ]]; then
    SAVED_EXAMINER=$($VENV_PYTHON -c "
import yaml
with open('$HOME/.aiir/config.yaml') as f:
    c = yaml.safe_load(f)
print(c.get('examiner', ''))
" 2>/dev/null || echo "")
    if [[ "$SAVED_EXAMINER" == "$EXAMINER" ]]; then
        ok "Examiner config verified: $EXAMINER"
    else
        warn "Examiner config mismatch"
        VERIFY_OK=false
    fi
else
    warn "Config file not found"
    VERIFY_OK=false
fi

# Summary
header "Installation Complete"

if $VERIFY_OK; then
    ok "All checks passed"
else
    warn "Some checks had warnings -- see output above"
fi

echo ""
echo "  Install location:  $INSTALL_DIR"
echo "  Virtual env:       $VENV_DIR"
echo "  Examiner:          $EXAMINER"
echo "  Config:            $HOME/.aiir/config.yaml"
echo ""
echo "  Run:               aiir --help"
echo ""
echo -e "${BOLD}Note:${NC} The aiir CLI reads from the case directory. Set AIIR_CASE_DIR"
echo "or use \`aiir case init\` to start an investigation."
echo ""

echo "Next steps:"
STEP=1
echo "  $STEP. Restart your shell (or: source ${SHELL_RC:-~/.bashrc})"
STEP=$((STEP + 1))
echo "  $STEP. Verify:  aiir --help"
STEP=$((STEP + 1))
echo "  $STEP. Start an investigation:  aiir case init --case-id my-case"
echo ""
