#!/usr/bin/env bash
#
# setup-sift.sh — AIIR Platform Installer for SIFT Workstation
#
# Installs local AIIR components, gateway, and optionally configures the
# LLM client on this machine (via 'aiir setup client').
#
# Three install modes:
#   Quick       — Core MCPs (~3 min)
#   Recommended — Adds RAG search + Windows triage (~30 min)
#   Custom      — Choose individual components (+ OpenCTI)
#
# Usage:
#   ./setup-sift.sh                                    # Interactive (default: Recommended)
#   ./setup-sift.sh --quick -y --examiner=steve        # Fully unattended quick
#   ./setup-sift.sh --recommended -y                   # Fully unattended recommended
#   ./setup-sift.sh --full                             # Custom mode (interactive)
#   ./setup-sift.sh --quick --manual-start             # No auto-start
#   ./setup-sift.sh --opencti                          # Add OpenCTI (triggers wizard)
#   ./setup-sift.sh --client=claude-code               # Install + configure LLM client
#   ./setup-sift.sh --remote                           # Install only, print remote instructions
#
set -euo pipefail

# =============================================================================
# Parse Arguments
# =============================================================================

AUTO_YES=false
MODE=""  # minimal, recommended, custom, or "" (show menu)
INSTALL_DIR_ARG=""
EXAMINER_ARG=""
MANUAL_START=false
ADD_OPENCTI=false
CLIENT_ARG=""
REMOTE_MODE=false

for arg in "$@"; do
    case "$arg" in
        -y|--yes)          AUTO_YES=true ;;
        --quick|--minimal) MODE="minimal" ;;
        --recommended)     MODE="recommended" ;;
        --full|--custom)   MODE="custom" ;;
        --manual-start)    MANUAL_START=true ;;
        --opencti)         ADD_OPENCTI=true ;;
        --remote)          REMOTE_MODE=true ;;
        --install-dir=*)   INSTALL_DIR_ARG="${arg#*=}" ;;
        --examiner=*)      EXAMINER_ARG="${arg#*=}" ;;
        --client=*)        CLIENT_ARG="${arg#*=}" ;;
        -h|--help)
            echo "Usage: setup-sift.sh [OPTIONS]"
            echo ""
            echo "Modes (pick one):"
            echo "  --quick         Core MCPs (~3 min)"
            echo "  --recommended   Adds RAG search + Windows triage (~30 min)"
            echo "  --full          Custom mode — choose individual components"
            echo ""
            echo "Options:"
            echo "  -y, --yes            Accept all defaults (unattended)"
            echo "  --manual-start       Don't auto-start gateway (default: auto-start)"
            echo "  --opencti            Add OpenCTI threat intelligence (triggers wizard)"
            echo "  --install-dir=PATH   Installation directory (default: ~/aiir)"
            echo "  --examiner=NAME      Examiner identity slug"
            echo "  --client=CLIENT      Configure LLM client (claude-code|claude-desktop|cursor)"
            echo "  --remote             Skip client config, print remote instructions"
            echo "  -h, --help           Show this help"
            exit 0
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

prompt_yn() {
    local msg="$1" default="${2:-y}"
    if $AUTO_YES; then
        [[ "$default" == "y" ]]
        return
    fi
    local suffix
    if [[ "$default" == "y" ]]; then suffix="[Y/n]"; else suffix="[y/N]"; fi
    read -rp "$(echo -e "${BOLD}$msg${NC} $suffix: ")" answer
    answer="${answer:-$default}"
    [[ "${answer,,}" == "y" ]]
}

# =============================================================================
# Banner
# =============================================================================

echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}  AIIR — Applied Incident Response Platform${NC}"
echo -e "${BOLD}  SIFT Workstation Installer${NC}"
echo -e "${BOLD}============================================================${NC}"
echo ""

# =============================================================================
# Mode Selection
# =============================================================================

if [[ -z "$MODE" ]]; then
    if $AUTO_YES; then
        MODE="recommended"
    else
        echo "  1. Quick        — Core MCPs (~3 min)"
        echo "  2. Recommended  — Adds RAG search + Windows triage (~30 min)"
        echo "  3. Custom       — Choose individual components"
        echo ""
        CHOICE=$(prompt "Choose" "2")
        case "$CHOICE" in
            1) MODE="minimal" ;;
            3) MODE="custom" ;;
            *) MODE="recommended" ;;
        esac
    fi
fi

info "Install mode: $MODE"
echo ""

# =============================================================================
# Prerequisites
# =============================================================================

header "Checking Prerequisites"

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
        echo "  Install: sudo apt install python3.10 python3.10-venv"
        exit 1
    fi
else
    err "Python 3 not found"
    echo "  Install: sudo apt install python3 python3-venv"
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

# venv
if $PYTHON -m venv --help &>/dev/null 2>&1; then
    ok "venv available"
else
    err "python3-venv not found"
    echo "  Install: sudo apt install python3-venv"
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

# Network
if git ls-remote https://github.com/AppliedIR/aiir.git HEAD &>/dev/null 2>&1; then
    ok "Network access to GitHub"
else
    warn "Cannot reach GitHub — installation requires network access"
    exit 1
fi

# =============================================================================
# Component Determination
# =============================================================================

# Flags for what to install (local MCPs)
INSTALL_SIFT=false
INSTALL_RAG=false
INSTALL_TRIAGE=false
INSTALL_OPENCTI=false

case "$MODE" in
    minimal)
        INSTALL_SIFT=true
        ;;
    recommended)
        INSTALL_SIFT=true
        INSTALL_RAG=true
        INSTALL_TRIAGE=true
        ;;
    custom)
        # Interactive component selection
        header "Select Components"

        echo -e "  ${BOLD}Always installed:${NC}"
        echo -e "    forensic-knowledge   — Forensic tool + artifact knowledge base"
        echo -e "    forensic-mcp         — Case management, findings, discipline"
        echo -e "    aiir CLI             — Human review, approval, configuration"
        echo -e "    aiir-gateway         — HTTP API for all MCPs"
        echo ""

        echo -e "  ${BOLD}Optional MCPs:${NC}"
        prompt_yn "    Install sift-mcp (forensic tool execution)?" "y" && INSTALL_SIFT=true
        prompt_yn "    Install forensic-rag-mcp (knowledge search — Sigma, MITRE, KAPE)?" "y" && INSTALL_RAG=true
        prompt_yn "    Install windows-triage-mcp (Windows baseline validation)?" "y" && INSTALL_TRIAGE=true
        prompt_yn "    Install opencti-mcp (threat intelligence — needs OpenCTI server)?" "n" && INSTALL_OPENCTI=true
        echo ""
        ;;
esac

# CLI flag overrides mode default
$ADD_OPENCTI && INSTALL_OPENCTI=true

# =============================================================================
# Install Directory
# =============================================================================

if [[ -n "$INSTALL_DIR_ARG" ]]; then
    INSTALL_DIR="$INSTALL_DIR_ARG"
elif [[ "$MODE" == "custom" ]]; then
    INSTALL_DIR=$(prompt "Installation directory" "$HOME/aiir")
else
    INSTALL_DIR="$HOME/aiir"
fi
INSTALL_DIR=$(realpath -m "$INSTALL_DIR")
mkdir -p "$INSTALL_DIR"

# =============================================================================
# Install Components
# =============================================================================

header "Installing Components"
info "Installing to $INSTALL_DIR"

GITHUB_ORG="https://github.com/AppliedIR"

install_mcp() {
    local name="$1"
    local repo="$2"
    local extras="${3:-}"
    local dir="$INSTALL_DIR/$name"

    echo ""
    info "Installing $name..."

    if [[ -d "$dir" ]]; then
        info "  Directory exists, pulling latest..."
        (cd "$dir" && git pull --quiet) || warn "Could not update $name (network issue?)"
    else
        git clone --quiet "$GITHUB_ORG/$repo.git" "$dir"
    fi

    if [[ ! -d "$dir/.venv" ]]; then
        $PYTHON -m venv "$dir/.venv"
    fi

    "$dir/.venv/bin/pip" install --quiet --upgrade pip
    if [[ -n "$extras" ]]; then
        "$dir/.venv/bin/pip" install --quiet -e "$dir[$extras]"
    else
        "$dir/.venv/bin/pip" install --quiet -e "$dir"
    fi

    # Smoke test
    local module
    case "$name" in
        forensic-rag-mcp)    module="rag_mcp" ;;
        windows-triage-mcp)  module="windows_triage" ;;
        forensic-mcp)        module="forensic_mcp" ;;
        forensic-knowledge)  module="forensic_knowledge" ;;
        sift-mcp)            module="sift_mcp" ;;
        opencti-mcp)         module="opencti_mcp" ;;
        aiir-gateway)        module="aiir_gateway" ;;
        aiir)                module="aiir_cli" ;;
        *)                   module=$(echo "$repo" | sed 's/-mcp$//' | sed 's/-/_/g') ;;
    esac

    if "$dir/.venv/bin/python" -c "import $module" 2>/dev/null; then
        ok "$name installed and importable"
    else
        warn "$name installed but import failed — check dependencies"
    fi
}

# forensic-knowledge is a shared dependency
install_mcp "forensic-knowledge" "forensic-knowledge"

# Always install: forensic-mcp, aiir CLI, aiir-gateway
install_mcp "forensic-mcp" "forensic-mcp" "dev"
install_mcp "aiir" "aiir" "dev"

# Mode-dependent components
$INSTALL_SIFT    && install_mcp "sift-mcp" "sift-mcp" "dev"
$INSTALL_RAG     && install_mcp "forensic-rag-mcp" "forensic-rag-mcp"
$INSTALL_TRIAGE  && install_mcp "windows-triage-mcp" "windows-triage-mcp"
$INSTALL_OPENCTI && install_mcp "opencti-mcp" "opencti-mcp"

# Always install gateway (after MCPs so we can configure it)
install_mcp "aiir-gateway" "aiir-gateway" "dev"

# Add aiir CLI to PATH
AIIR_BIN="$INSTALL_DIR/aiir/.venv/bin"
if [[ ":$PATH:" != *":$AIIR_BIN:"* ]]; then
    SHELL_RC=""
    if [[ -f "$HOME/.bashrc" ]]; then SHELL_RC="$HOME/.bashrc";
    elif [[ -f "$HOME/.zshrc" ]]; then SHELL_RC="$HOME/.zshrc"; fi

    if [[ -n "$SHELL_RC" ]]; then
        if ! grep -q "aiir/.venv/bin" "$SHELL_RC" 2>/dev/null; then
            echo "" >> "$SHELL_RC"
            echo "# AIIR Platform" >> "$SHELL_RC"
            echo "export PATH=\"$AIIR_BIN:\$PATH\"" >> "$SHELL_RC"
            ok "Added aiir to PATH in $SHELL_RC"
        fi
    fi
    export PATH="$AIIR_BIN:$PATH"
fi

# =============================================================================
# Heavy Setup (mode-dependent)
# =============================================================================

if $INSTALL_RAG; then
    if [[ "$MODE" == "custom" ]]; then
        header "forensic-rag-mcp Index"
        echo "forensic-rag-mcp needs to build a search index (~2GB disk for ML model)."
        echo "  Build now:  downloads model + builds index (takes a few minutes)"
        echo "  Skip:       build later with: cd $INSTALL_DIR/forensic-rag-mcp && .venv/bin/python -m rag_mcp.build"
        echo ""
        if prompt_yn "Build index now?" "y"; then
            info "Building forensic-rag index (this may take a few minutes)..."
            (cd "$INSTALL_DIR/forensic-rag-mcp" && .venv/bin/python -m rag_mcp.build) && \
                ok "Index built" || warn "Index build failed — you can retry later"
        else
            info "Skipping index build."
        fi
    else
        echo ""
        info "forensic-rag-mcp: index will build on first use (~2 min, ~2GB download)"
        info "  Or build now:  cd $INSTALL_DIR/forensic-rag-mcp && .venv/bin/python -m rag_mcp.build"
    fi
fi

if $INSTALL_TRIAGE; then
    if [[ "$MODE" == "custom" ]]; then
        header "windows-triage-mcp Databases"
        echo "windows-triage-mcp needs Windows baseline databases."
        echo "  Set up now: clone data repos + import (takes 30-60 minutes)"
        echo "  Skip:       see $INSTALL_DIR/windows-triage-mcp/SETUP.md"
        echo ""
        if prompt_yn "Set up databases now?" "n"; then
            WT_DIR="$INSTALL_DIR/windows-triage-mcp"
            DATA_DIR="$WT_DIR/data/sources"
            mkdir -p "$DATA_DIR"

            info "Cloning VanillaWindowsReference..."
            if [[ ! -d "$DATA_DIR/VanillaWindowsReference" ]]; then
                git clone --quiet https://github.com/AndrewRathbun/VanillaWindowsReference.git "$DATA_DIR/VanillaWindowsReference"
            fi

            info "Cloning LOLBAS, LOLDrivers, HijackLibs..."
            for repo in LOLBAS LOLDrivers HijackLibs; do
                if [[ ! -d "$DATA_DIR/$repo" ]]; then
                    git clone --quiet "https://github.com/LOLBAS-Project/$repo.git" "$DATA_DIR/$repo" 2>/dev/null || \
                    git clone --quiet "https://github.com/magicsword-io/$repo.git" "$DATA_DIR/$repo" 2>/dev/null || \
                    warn "Could not clone $repo"
                fi
            done

            info "Initializing databases and importing..."
            (cd "$WT_DIR" && .venv/bin/python scripts/init_databases.py && \
                .venv/bin/python scripts/import_all.py --skip-registry) && \
                ok "Databases imported" || warn "Database import had issues — see output above"
        else
            info "Skipping database setup."
        fi
    else
        echo ""
        info "windows-triage-mcp: databases can be imported later"
        info "  See: $INSTALL_DIR/windows-triage-mcp/SETUP.md"
    fi
fi

# =============================================================================
# OpenCTI Credential Wizard
# =============================================================================

OPENCTI_URL=""
OPENCTI_TOKEN=""

if $INSTALL_OPENCTI; then
    header "OpenCTI Configuration"
    echo "opencti-mcp needs an OpenCTI server URL and API token."
    echo ""
    OPENCTI_URL=$(prompt "OpenCTI URL (e.g., https://opencti.example.com)" "")
    if [[ -n "$OPENCTI_URL" ]]; then
        read -rsp "OpenCTI API Token: " OPENCTI_TOKEN
        echo ""

        # Test connectivity (token passed via env, not CLI arg)
        if OPENCTI_URL="$OPENCTI_URL" OPENCTI_TOKEN="$OPENCTI_TOKEN" \
            "$INSTALL_DIR/opencti-mcp/.venv/bin/python" -c "
from opencti_mcp.config import Config; from opencti_mcp.client import OpenCTIClient
c = OpenCTIClient(Config.from_env())
r = c.validate_connection(skip_connectivity=False)
print('OK' if r['valid'] else 'FAIL')
" 2>/dev/null | grep -q "OK"; then
            ok "OpenCTI connection verified"
        else
            warn "Could not connect to OpenCTI — check URL and token"
        fi
    else
        info "Skipping. Set OPENCTI_URL and OPENCTI_TOKEN in gateway.yaml later."
        OPENCTI_URL=""
        OPENCTI_TOKEN=""
    fi
fi

# =============================================================================
# Examiner Identity
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
    EXAMINER=$(whoami | tr '[:upper:]' '[:lower:]')
fi

# Save to config
mkdir -p "$HOME/.aiir"
cat > "$HOME/.aiir/config.yaml" << EOF
examiner: $EXAMINER
EOF
ok "Saved examiner identity: $EXAMINER"

# Add AIIR_EXAMINER to shell profile
SHELL_RC=""
if [[ -f "$HOME/.bashrc" ]]; then SHELL_RC="$HOME/.bashrc";
elif [[ -f "$HOME/.zshrc" ]]; then SHELL_RC="$HOME/.zshrc"; fi

if [[ -n "$SHELL_RC" ]] && ! grep -q "AIIR_EXAMINER" "$SHELL_RC" 2>/dev/null; then
    echo "export AIIR_EXAMINER=\"$EXAMINER\"" >> "$SHELL_RC"
    ok "Added AIIR_EXAMINER to $SHELL_RC"
fi
export AIIR_EXAMINER="$EXAMINER"

# =============================================================================
# Gateway Configuration and Startup
# =============================================================================

header "Gateway Setup"

GATEWAY_DIR="$INSTALL_DIR/aiir-gateway"
GATEWAY_PYTHON="$GATEWAY_DIR/.venv/bin/python"
GATEWAY_CONFIG="$GATEWAY_DIR/config/gateway.yaml"
GATEWAY_PORT=4508

# Generate gateway.yaml with all installed MCPs as backends
info "Generating gateway configuration..."
mkdir -p "$(dirname "$GATEWAY_CONFIG")"

$GATEWAY_PYTHON -c "
import yaml

config = {
    'gateway': {
        'host': '127.0.0.1',
        'port': $GATEWAY_PORT,
        'log_level': 'INFO',
    },
    'backends': {},
}

# Local stdio backends
backends = {
    'forensic-mcp': ('forensic_mcp', '$INSTALL_DIR/forensic-mcp/.venv/bin/python'),
}
if '$INSTALL_SIFT' == 'true':
    backends['sift-mcp'] = ('sift_mcp', '$INSTALL_DIR/sift-mcp/.venv/bin/python')
if '$INSTALL_RAG' == 'true':
    backends['forensic-rag'] = ('rag_mcp', '$INSTALL_DIR/forensic-rag-mcp/.venv/bin/python')
if '$INSTALL_TRIAGE' == 'true':
    backends['windows-triage'] = ('windows_triage', '$INSTALL_DIR/windows-triage-mcp/.venv/bin/python')
if '$INSTALL_OPENCTI' == 'true':
    backends['opencti-mcp'] = ('opencti_mcp', '$INSTALL_DIR/opencti-mcp/.venv/bin/python')

for name, (module, python_path) in backends.items():
    entry = {
        'type': 'stdio',
        'command': python_path,
        'args': ['-m', module],
        'enabled': True,
    }
    if name == 'opencti-mcp':
        url = '$OPENCTI_URL'
        token = '$OPENCTI_TOKEN'
        if url:
            entry['env'] = {'OPENCTI_URL': url, 'OPENCTI_TOKEN': token}
    config['backends'][name] = entry

with open('$GATEWAY_CONFIG', 'w') as f:
    yaml.dump(config, f, default_flow_style=False, sort_keys=False)
" 2>/dev/null

chmod 600 "$GATEWAY_CONFIG"
ok "Generated: $GATEWAY_CONFIG"

# Generate startup script (useful for both manual and auto modes)
GATEWAY_START="$INSTALL_DIR/start-gateway.sh"
cat > "$GATEWAY_START" << SCRIPT
#!/usr/bin/env bash
# Start AIIR Gateway
export AIIR_EXAMINER="$EXAMINER"
exec "$GATEWAY_PYTHON" -m aiir_gateway --config "$GATEWAY_CONFIG"
SCRIPT
chmod +x "$GATEWAY_START"

# Start gateway to verify it works
info "Starting gateway on port $GATEWAY_PORT..."
"$GATEWAY_PYTHON" -m aiir_gateway --config "$GATEWAY_CONFIG" &
GATEWAY_PID=$!
sleep 2

if kill -0 "$GATEWAY_PID" 2>/dev/null; then
    if curl -sf "http://127.0.0.1:$GATEWAY_PORT/health" &>/dev/null; then
        ok "Gateway running on port $GATEWAY_PORT"
    else
        warn "Gateway started but health check failed"
    fi
else
    warn "Gateway failed to start — check $GATEWAY_CONFIG"
fi

# Determine auto-start behavior
AUTOSTART=true
if $MANUAL_START; then
    AUTOSTART=false
elif [[ "$MODE" == "custom" ]]; then
    echo ""
    echo "  1. Auto-start at boot (systemd service)"
    echo "  2. Manual start (use start-gateway.sh)"
    echo ""
    START_CHOICE=$(prompt "Choose" "1")
    [[ "$START_CHOICE" != "1" ]] && AUTOSTART=false
fi

if $AUTOSTART; then
    # Install systemd user service
    SYSTEMD_DIR="$HOME/.config/systemd/user"
    mkdir -p "$SYSTEMD_DIR"

    cat > "$SYSTEMD_DIR/aiir-gateway.service" << SERVICE
[Unit]
Description=AIIR Gateway
After=network.target

[Service]
ExecStart=$GATEWAY_PYTHON -m aiir_gateway --config $GATEWAY_CONFIG
Environment=AIIR_EXAMINER=$EXAMINER
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
SERVICE

    # Stop the test process — systemd will manage it now
    kill "$GATEWAY_PID" 2>/dev/null || true
    wait "$GATEWAY_PID" 2>/dev/null || true

    systemctl --user daemon-reload
    systemctl --user enable aiir-gateway.service 2>/dev/null && \
        ok "Systemd service enabled (auto-start at login)"
    systemctl --user start aiir-gateway.service 2>/dev/null && \
        ok "Gateway started via systemd" || \
        warn "Could not start via systemd — use $GATEWAY_START manually"

    # Enable lingering so service runs without active login session
    if command -v loginctl &>/dev/null; then
        loginctl enable-linger "$(whoami)" 2>/dev/null && \
            ok "Linger enabled (gateway runs without active login)" || true
    fi
else
    ok "Manual start: $GATEWAY_START"
    info "Gateway is running now (PID $GATEWAY_PID) — will stop on logout"
fi

# =============================================================================
# Team Deployment (Custom mode only)
# =============================================================================

if [[ "$MODE" == "custom" ]]; then
    echo ""
    if prompt_yn "Set up for team collaboration?" "n"; then
        header "Team Deployment"

        CASE_DIR=$(prompt "Shared case directory" "/cases")

        echo ""
        echo "To share cases with other examiners, export the case directory via NFS or Samba."
        echo ""
        echo -e "${BOLD}NFS:${NC}"
        echo "  Add to /etc/exports:"
        echo "    $CASE_DIR *(rw,sync,no_subtree_check,no_root_squash)"
        echo "  Then run: sudo exportfs -ra"
        echo ""
        echo -e "${BOLD}Samba:${NC}"
        echo "  Add to /etc/samba/smb.conf:"
        echo "    [$(basename "$CASE_DIR")]"
        echo "        path = $CASE_DIR"
        echo "        browsable = yes"
        echo "        writable = yes"
        echo "        valid users = @forensics"
        echo "  Then run: sudo systemctl restart smbd"
        echo ""

        # Test connectivity to Windows workstation
        if prompt_yn "Test connectivity to a Windows workstation?" "n"; then
            WIN_HOST=$(prompt "Windows workstation IP or hostname" "")
            if [[ -n "$WIN_HOST" ]]; then
                WIN_PORT=$(prompt "wintools-mcp port" "4624")
                if curl -sf "http://$WIN_HOST:$WIN_PORT/health" &>/dev/null; then
                    ok "Connected to wintools-mcp at $WIN_HOST:$WIN_PORT"
                else
                    warn "Cannot reach $WIN_HOST:$WIN_PORT — ensure wintools-mcp is running"
                fi
            fi
        fi
    fi
fi

# =============================================================================
# LLM Client Configuration
# =============================================================================

AIIR_CLI="$INSTALL_DIR/aiir/.venv/bin/aiir"
CLIENT_CONFIGURED=false

if $REMOTE_MODE; then
    # --remote: skip local client config, print instructions for remote machine
    header "Remote Client Instructions"
    echo "To configure your LLM client on your remote machine:"
    echo ""
    echo "  pip install aiir"
    echo "  aiir setup client --sift=http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'THIS_IP'):$GATEWAY_PORT"
    echo ""
    echo "Replace the IP with this machine's address if auto-detect is wrong."
elif [[ -n "$CLIENT_ARG" ]]; then
    # --client=X: implies local, pass through
    header "LLM Client Configuration"
    "$AIIR_CLI" setup client \
        --sift="http://127.0.0.1:$GATEWAY_PORT" \
        --client="$CLIENT_ARG" \
        --examiner="$EXAMINER" \
        -y && CLIENT_CONFIGURED=true || warn "Client configuration failed"
elif [[ "$MODE" == "minimal" ]]; then
    # Quick mode: auto-configure Claude Code
    header "LLM Client Configuration"
    info "Auto-configuring Claude Code..."
    "$AIIR_CLI" setup client \
        --sift="http://127.0.0.1:$GATEWAY_PORT" \
        --client=claude-code \
        --examiner="$EXAMINER" \
        -y && CLIENT_CONFIGURED=true || warn "Client configuration failed"
else
    # Recommended / Custom: ask
    header "LLM Client Configuration"
    if $AUTO_YES; then
        info "Auto-configuring Claude Code..."
        "$AIIR_CLI" setup client \
            --sift="http://127.0.0.1:$GATEWAY_PORT" \
            --client=claude-code \
            --examiner="$EXAMINER" \
            -y && CLIENT_CONFIGURED=true || warn "Client configuration failed"
    elif prompt_yn "Working from this machine? Configure LLM client now?" "y"; then
        "$AIIR_CLI" setup client \
            --sift="http://127.0.0.1:$GATEWAY_PORT" \
            --examiner="$EXAMINER" && CLIENT_CONFIGURED=true || warn "Client configuration failed"
    else
        echo ""
        echo "To configure your LLM client on your remote machine:"
        echo ""
        echo "  pip install aiir"
        echo "  aiir setup client --sift=http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'THIS_IP'):$GATEWAY_PORT"
        echo ""
    fi
fi

# =============================================================================
# Summary
# =============================================================================

header "Installation Complete"

echo "Installed components:"
ok "forensic-knowledge"
ok "forensic-mcp"
ok "aiir CLI"
ok "aiir-gateway (port $GATEWAY_PORT)"
$INSTALL_SIFT    && ok "sift-mcp"
$INSTALL_RAG     && ok "forensic-rag-mcp"
$INSTALL_TRIAGE  && ok "windows-triage-mcp"
$INSTALL_OPENCTI && ok "opencti-mcp"

echo ""
echo "Examiner:    $EXAMINER"
echo "Install dir: $INSTALL_DIR"
echo "Gateway:     http://127.0.0.1:$GATEWAY_PORT"
if $AUTOSTART; then
    echo "Auto-start:  enabled (systemd)"
else
    echo "Start:       $GATEWAY_START"
fi
if $CLIENT_CONFIGURED; then
    echo "LLM client:  configured"
fi
echo ""

echo "Next steps:"
STEP=1
echo "  $STEP. Restart your shell (or: source ${SHELL_RC:-~/.bashrc})"
if ! $CLIENT_CONFIGURED && ! $REMOTE_MODE; then
    STEP=$((STEP + 1))
    echo "  $STEP. Configure your LLM client:  aiir setup client"
fi
STEP=$((STEP + 1))
echo "  $STEP. Verify installation:         aiir setup test"

if $INSTALL_RAG && [[ "$MODE" != "custom" ]]; then
    echo ""
    echo "Deferred setup:"
    echo "  RAG index:   cd $INSTALL_DIR/forensic-rag-mcp && .venv/bin/python -m rag_mcp.build"
fi
if $INSTALL_TRIAGE && [[ "$MODE" != "custom" ]]; then
    echo "  Triage DBs:  see $INSTALL_DIR/windows-triage-mcp/SETUP.md"
fi

echo ""
echo -e "${BOLD}Documentation:${NC} $INSTALL_DIR/forensic-mcp/AGENTS.md"
echo ""
