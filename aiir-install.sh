#!/usr/bin/env bash
#
# aiir-install.sh — AIIR CLI Installer
#
# Installs the aiir CLI into the shared ~/.aiir/venv/ (creating it if needed),
# sets examiner identity, and runs the setup wizard.
#
# Usage:
#   ./aiir-install.sh                    # Interactive
#   ./aiir-install.sh --examiner=steve   # Set examiner non-interactively
#   ./aiir-install.sh -y                 # Accept all defaults
#   ./aiir-install.sh -h                 # Help
#
set -euo pipefail

# =============================================================================
# Parse Arguments
# =============================================================================

AUTO_YES=false
VENV_DIR=""
INSTALL_DIR=""
EXAMINER_ARG=""

for arg in "$@"; do
    case "$arg" in
        -y|--yes)          AUTO_YES=true ;;
        --venv=*)          VENV_DIR="${arg#*=}" ;;
        --install-dir=*)   INSTALL_DIR="${arg#*=}" ;;
        --examiner=*)      EXAMINER_ARG="${arg#*=}" ;;
        -h|--help)
            echo "Usage: aiir-install.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --venv=X          Override venv path (default: ~/.aiir/venv)"
            echo "  --install-dir=X   Override clone dir (default: ~/.aiir/src/aiir)"
            echo "  --examiner=NAME   Set examiner identity non-interactively"
            echo "  -y, --yes         Accept all defaults"
            echo "  -h, --help        Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg (use -h for help)"
            exit 1
            ;;
    esac
done

# Defaults
[[ -z "$VENV_DIR" ]] && VENV_DIR="$HOME/.aiir/venv"
[[ -z "$INSTALL_DIR" ]] && INSTALL_DIR="$HOME/.aiir/src/aiir"

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

# =============================================================================
# Banner
# =============================================================================

echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}  AIIR — CLI Installer${NC}"
echo -e "${BOLD}  Applied Incident Investigation and Response${NC}"
echo -e "${BOLD}============================================================${NC}"
echo ""

# =============================================================================
# Phase 1: Prerequisites
# =============================================================================

header "Checking Prerequisites"

# Python 3.11+
if command -v python3 &>/dev/null; then
    PYTHON=$(command -v python3)
    PY_VERSION=$($PYTHON -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PY_MAJOR=$($PYTHON -c 'import sys; print(sys.version_info.major)')
    PY_MINOR=$($PYTHON -c 'import sys; print(sys.version_info.minor)')
    if (( PY_MAJOR > 3 || (PY_MAJOR == 3 && PY_MINOR >= 11) )); then
        ok "Python $PY_VERSION ($PYTHON)"
    else
        err "Python 3.11+ required (found $PY_VERSION)"
        exit 1
    fi
else
    err "Python 3 not found"
    exit 1
fi

# pip
if $PYTHON -m pip --version &>/dev/null; then
    ok "pip available"
else
    err "pip not found"
    echo "  Install: sudo apt install python3-pip"
    exit 1
fi

# git
if command -v git &>/dev/null; then
    ok "git $(git --version | awk '{print $3}')"
else
    err "git not found"
    echo "  Install: sudo apt install git"
    exit 1
fi

# =============================================================================
# Phase 2: Virtual Environment
# =============================================================================

header "Virtual Environment"

VENV_DIR=$(realpath -m "$VENV_DIR")

if [[ -d "$VENV_DIR" ]] && [[ -f "$VENV_DIR/bin/python" ]]; then
    ok "Reusing existing venv at $VENV_DIR"
else
    info "Creating virtual environment at $VENV_DIR..."
    mkdir -p "$(dirname "$VENV_DIR")"
    if ! $PYTHON -m venv "$VENV_DIR"; then
        err "Failed to create virtual environment"
        echo "  Ensure python3-venv is installed: sudo apt install python3-venv"
        exit 1
    fi
    "$VENV_DIR/bin/pip" install --progress-bar off --upgrade pip >/dev/null 2>&1 || true
    ok "Virtual environment created at $VENV_DIR"
fi

VENV_PIP="$VENV_DIR/bin/pip"
VENV_PYTHON="$VENV_DIR/bin/python"

# =============================================================================
# Phase 3: Clone + Install
# =============================================================================

header "Installing aiir CLI"

REPO_URL="https://github.com/AppliedIR/aiir.git"
INSTALL_DIR=$(realpath -m "$INSTALL_DIR")
mkdir -p "$(dirname "$INSTALL_DIR")"

if [[ -d "$INSTALL_DIR/.git" ]]; then
    info "Repository exists at $INSTALL_DIR. Pulling latest..."
    if (cd "$INSTALL_DIR" && git pull --quiet); then
        ok "Repository updated"
    else
        warn "Could not update repository. Continuing with existing code."
    fi
elif [[ -d "$INSTALL_DIR" ]] && [[ ! -d "$INSTALL_DIR/.git" ]]; then
    err "$INSTALL_DIR exists but is not a git repository"
    echo "  Remove it or choose a different --install-dir"
    exit 1
else
    info "Cloning aiir CLI..."
    if ! git clone --quiet "$REPO_URL" "$INSTALL_DIR"; then
        err "Failed to clone aiir repository"
        echo "  Check network access and try again"
        exit 1
    fi
    ok "Repository cloned to $INSTALL_DIR"
fi

echo ""
info "Installing aiir CLI into venv..."
if ! $VENV_PIP install --progress-bar off -e "$INSTALL_DIR" >/dev/null; then
    err "Failed to install aiir CLI"
    echo "  Check pip output: $VENV_PIP install -e $INSTALL_DIR"
    exit 1
fi

# Smoke test
if "$VENV_PYTHON" -c "import aiir_cli" 2>/dev/null; then
    ok "aiir CLI installed"
else
    err "aiir CLI import failed"
    exit 1
fi

AIIR_CMD="$VENV_DIR/bin/aiir"

# =============================================================================
# Phase 4: Add venv to PATH
# =============================================================================

AIIR_BIN="$VENV_DIR/bin"
SHELL_RC=""
if [[ -f "$HOME/.bashrc" ]]; then SHELL_RC="$HOME/.bashrc";
elif [[ -f "$HOME/.zshrc" ]]; then SHELL_RC="$HOME/.zshrc"; fi

if [[ ":$PATH:" != *":$AIIR_BIN:"* ]]; then
    if [[ -n "$SHELL_RC" ]]; then
        if ! grep -q "$VENV_DIR/bin" "$SHELL_RC" 2>/dev/null; then
            echo "" >> "$SHELL_RC"
            echo "# AIIR Platform" >> "$SHELL_RC"
            echo "export PATH=\"$AIIR_BIN:\$PATH\"" >> "$SHELL_RC"
            ok "Added venv to PATH in $SHELL_RC"
        fi
    fi
    export PATH="$AIIR_BIN:$PATH"
fi

# =============================================================================
# Phase 5: Examiner Identity
# =============================================================================

header "Examiner Identity"

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
CONFIG_FILE="$HOME/.aiir/config.yaml"
if [[ -f "$CONFIG_FILE" ]] && grep -q "^examiner:" "$CONFIG_FILE" 2>/dev/null; then
    sed -i "s/^examiner:.*$/examiner: $EXAMINER/" "$CONFIG_FILE"
else
    echo "examiner: $EXAMINER" >> "$CONFIG_FILE"
fi
ok "Saved examiner identity: $EXAMINER"

# Add or update AIIR_EXAMINER in shell profile
if [[ -n "$SHELL_RC" ]]; then
    if grep -q "AIIR_EXAMINER" "$SHELL_RC" 2>/dev/null; then
        sed -i "s/^export AIIR_EXAMINER=.*$/export AIIR_EXAMINER=\"$EXAMINER\"/" "$SHELL_RC"
        ok "Updated AIIR_EXAMINER in $SHELL_RC"
    else
        echo "export AIIR_EXAMINER=\"$EXAMINER\"" >> "$SHELL_RC"
        ok "Added AIIR_EXAMINER to $SHELL_RC"
    fi
fi
export AIIR_EXAMINER="$EXAMINER"

# =============================================================================
# Phase 6: Setup Wizard
# =============================================================================

header "Setup Wizard"

if [[ -f "$HOME/.aiir/manifest.json" ]]; then
    info "SIFT platform detected (manifest.json found)"
fi

if $AUTO_YES; then
    info "Skipping interactive setup (-y). Run 'aiir setup' to configure later."
else
    echo "The setup wizard discovers installed MCPs and configures your LLM client."
    echo "You can run it now or later with: aiir setup client"
    echo ""
    read -rp "$(echo -e "${BOLD}Run setup wizard now?${NC} [Y/n]: ")" RUN_SETUP
    RUN_SETUP="${RUN_SETUP:-y}"
    if [[ "${RUN_SETUP,,}" == "y" ]]; then
        "$AIIR_CMD" setup client || warn "Setup wizard encountered an issue. Run 'aiir setup client' to retry."
    else
        info "Skipped. Run 'aiir setup client' when ready."
    fi
fi

# =============================================================================
# Summary
# =============================================================================

header "Installation Complete"

echo "Examiner:    $EXAMINER"
echo "CLI:         $AIIR_CMD"
echo "Venv:        $VENV_DIR"
echo "Config:      $CONFIG_FILE"

echo ""
echo "Next steps:"
STEP=1
echo "  $STEP. Restart your shell (or: source ${SHELL_RC:-~/.bashrc})"
STEP=$((STEP + 1))
echo "  $STEP. Configure your LLM client:  aiir setup client"
STEP=$((STEP + 1))
echo "  $STEP. Verify installation:         aiir setup test"
echo ""
