#!/usr/bin/env bash
#
# setup-sift.sh — AIIR Platform Installer for SIFT Workstation
#
# Three install modes:
#   Minimal     — Core MCPs + report writing (~3 min)
#   Recommended — Adds RAG search, Windows triage, MS Learn (~30 min)
#   Custom      — Choose individual components
#
# Usage:
#   ./setup-sift.sh                        # Interactive (default: Recommended)
#   ./setup-sift.sh --minimal              # Fire-and-forget core install
#   ./setup-sift.sh --minimal -y           # Fully unattended minimal
#   ./setup-sift.sh --recommended -y       # Fully unattended recommended
#   ./setup-sift.sh --full                 # Custom mode
#   ./setup-sift.sh --opencti --remnux     # Add optional components
#
set -euo pipefail

# =============================================================================
# Parse Arguments
# =============================================================================

AUTO_YES=false
MODE=""  # minimal, recommended, custom, or "" (show menu)
INSTALL_DIR_ARG=""
EXAMINER_ARG=""
ADD_OPENCTI=false
ADD_REMNUX=false

for arg in "$@"; do
    case "$arg" in
        -y|--yes)         AUTO_YES=true ;;
        --minimal|--quick) MODE="minimal" ;;
        --recommended)    MODE="recommended" ;;
        --full|--custom)  MODE="custom" ;;
        --opencti)        ADD_OPENCTI=true ;;
        --remnux)         ADD_REMNUX=true ;;
        --install-dir=*)  INSTALL_DIR_ARG="${arg#*=}" ;;
        --examiner=*)     EXAMINER_ARG="${arg#*=}" ;;
        -h|--help)
            echo "Usage: setup-sift.sh [OPTIONS]"
            echo ""
            echo "Modes (pick one):"
            echo "  --minimal       Core MCPs + report writing (~3 min)"
            echo "  --recommended   Adds RAG search, Windows triage, MS Learn (~30 min)"
            echo "  --full          Custom mode — choose individual components"
            echo ""
            echo "Options:"
            echo "  -y, --yes           Accept all defaults (unattended)"
            echo "  --opencti           Add OpenCTI threat intelligence"
            echo "  --remnux            Add REMnux malware analysis"
            echo "  --install-dir=PATH  Installation directory (default: ~/aiir)"
            echo "  --examiner=NAME     Examiner identity slug"
            echo "  -h, --help          Show this help"
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
DIM='\033[2m'
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
        echo "  1. Minimal      — Core MCPs + report writing (~3 min)"
        echo "  2. Recommended  — Adds RAG search, Windows triage, MS Learn (~30 min)"
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
INSTALL_REMNUX=false
INSTALL_GATEWAY=false

# Flags for remote MCPs to include in config
INCLUDE_ZELTSER=false    # zeltser-ir-writing (report writing)
INCLUDE_MSLEARN=false    # microsoft-learn (MS docs)

case "$MODE" in
    minimal)
        INSTALL_SIFT=true
        INCLUDE_ZELTSER=true
        ;;
    recommended)
        INSTALL_SIFT=true
        INSTALL_RAG=true
        INSTALL_TRIAGE=true
        INCLUDE_ZELTSER=true
        INCLUDE_MSLEARN=true
        ;;
    custom)
        # Interactive component selection
        header "Select Components"

        echo -e "  ${BOLD}Local MCPs:${NC}"
        echo -e "    forensic-mcp        — Case management, findings, discipline ${DIM}(always installed)${NC}"
        echo -e "    aiir CLI             — Human review, approval, configuration ${DIM}(always installed)${NC}"
        echo ""

        prompt_yn "    Install sift-mcp (forensic tool execution)?" "y" && INSTALL_SIFT=true
        prompt_yn "    Install forensic-rag-mcp (knowledge search — Sigma, MITRE, KAPE)?" "y" && INSTALL_RAG=true
        prompt_yn "    Install windows-triage-mcp (Windows baseline validation)?" "y" && INSTALL_TRIAGE=true
        prompt_yn "    Install opencti-mcp (threat intelligence — needs OpenCTI server)?" "n" && INSTALL_OPENCTI=true
        prompt_yn "    Install aiir-gateway (HTTP gateway — multi-machine / OpenWebUI)?" "n" && INSTALL_GATEWAY=true

        echo ""
        echo -e "  ${BOLD}Remote MCPs (zero-config):${NC}"
        INCLUDE_ZELTSER=true
        INCLUDE_MSLEARN=true
        ok "zeltser-ir-writing  — IR report writing guidance"
        ok "microsoft-learn     — Microsoft technical documentation"

        echo ""
        echo -e "  ${BOLD}Remote MCPs (needs credentials):${NC}"
        prompt_yn "    Add remnux-mcp (malware analysis — needs REMnux instance)?" "n" && INSTALL_REMNUX=true
        echo ""
        ;;
esac

# CLI flags override mode defaults
$ADD_OPENCTI && INSTALL_OPENCTI=true
$ADD_REMNUX && INSTALL_REMNUX=true

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

# Always install forensic-mcp and aiir CLI
install_mcp "forensic-mcp" "forensic-mcp" "dev"
install_mcp "aiir" "aiir" "dev"

# Mode-dependent components
$INSTALL_SIFT    && install_mcp "sift-mcp" "sift-mcp" "dev"
$INSTALL_RAG     && install_mcp "forensic-rag-mcp" "forensic-rag-mcp"
$INSTALL_TRIAGE  && install_mcp "windows-triage-mcp" "windows-triage-mcp"
$INSTALL_OPENCTI && install_mcp "opencti-mcp" "opencti-mcp"
$INSTALL_GATEWAY && install_mcp "aiir-gateway" "aiir-gateway" "dev"

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
# Credential Wizards (Custom mode / --opencti / --remnux flags)
# =============================================================================

OPENCTI_URL=""
OPENCTI_TOKEN=""
REMNUX_HOST=""
REMNUX_PORT="3000"
REMNUX_TOKEN=""

if $INSTALL_OPENCTI; then
    header "OpenCTI Configuration"
    echo "opencti-mcp needs an OpenCTI server URL and API token."
    echo ""
    OPENCTI_URL=$(prompt "OpenCTI URL (e.g., https://opencti.example.com)" "")
    if [[ -n "$OPENCTI_URL" ]]; then
        read -rsp "OpenCTI API Token: " OPENCTI_TOKEN
        echo ""

        # Test connectivity
        if "$INSTALL_DIR/opencti-mcp/.venv/bin/python" -c "
import os; os.environ['OPENCTI_URL']='$OPENCTI_URL'; os.environ['OPENCTI_TOKEN']='$OPENCTI_TOKEN'
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
        info "Skipping. Set OPENCTI_URL and OPENCTI_TOKEN env vars later."
        OPENCTI_URL=""
        OPENCTI_TOKEN=""
    fi
fi

if $INSTALL_REMNUX; then
    header "REMnux Configuration"
    echo "remnux-mcp connects to a REMnux instance for malware analysis."
    echo "You need the host/IP, port, and bearer token from the REMnux MCP server."
    echo ""
    REMNUX_HOST=$(prompt "REMnux host (IP or hostname)" "")
    if [[ -n "$REMNUX_HOST" ]]; then
        REMNUX_PORT=$(prompt "REMnux port" "3000")
        read -rsp "REMnux bearer token: " REMNUX_TOKEN
        echo ""

        # Test connectivity
        if curl -sf "http://$REMNUX_HOST:$REMNUX_PORT/health" &>/dev/null; then
            ok "REMnux reachable at $REMNUX_HOST:$REMNUX_PORT"
        else
            warn "Cannot reach $REMNUX_HOST:$REMNUX_PORT — ensure remnux-mcp-server is running"
        fi
    else
        info "Skipping. Configure remnux-mcp manually later."
        REMNUX_HOST=""
    fi
fi

# =============================================================================
# LLM Client Configuration
# =============================================================================

header "Configure LLM Client"

echo "Which LLM client do you use?"
echo "  1. Claude Code (.mcp.json in project directory)"
echo "  2. Claude Desktop (~/.config/claude/claude_desktop_config.json)"
echo "  3. Cursor (.cursor/mcp.json in project directory)"
echo "  4. Other / manual (prints config to paste)"
echo "  5. Skip (configure later with: aiir setup)"
echo ""
CLIENT_CHOICE=$(prompt "Choose" "1")

generate_mcp_config() {
    # Build JSON config for all installed MCPs
    local output_file="$1"
    local servers=""

    add_stdio_server() {
        local name="$1" module="$2" venv_dir="$3"
        local python_path="$venv_dir/.venv/bin/python"
        if [[ -n "$servers" ]]; then servers="$servers,"; fi
        local entry="\"$name\":{\"command\":\"$python_path\",\"args\":[\"-m\",\"$module\"]"

        # Add env vars for opencti
        if [[ "$name" == "opencti-mcp" && -n "${OPENCTI_URL:-}" ]]; then
            entry="$entry,\"env\":{\"OPENCTI_URL\":\"$OPENCTI_URL\",\"OPENCTI_TOKEN\":\"$OPENCTI_TOKEN\"}"
        fi

        entry="$entry}"
        servers="$servers$entry"
    }

    add_http_server() {
        local name="$1" url="$2"
        if [[ -n "$servers" ]]; then servers="$servers,"; fi
        servers="$servers\"$name\":{\"type\":\"http\",\"url\":\"$url\"}"
    }

    add_streamable_http_server() {
        local name="$1" url="$2" token="$3"
        if [[ -n "$servers" ]]; then servers="$servers,"; fi
        servers="$servers\"$name\":{\"type\":\"streamable-http\",\"url\":\"$url\",\"headers\":{\"Authorization\":\"Bearer $token\"}}"
    }

    # Local stdio MCPs (always)
    add_stdio_server "forensic-mcp" "forensic_mcp" "$INSTALL_DIR/forensic-mcp"
    $INSTALL_SIFT    && add_stdio_server "sift-mcp" "sift_mcp" "$INSTALL_DIR/sift-mcp"
    $INSTALL_RAG     && add_stdio_server "forensic-rag" "rag_mcp" "$INSTALL_DIR/forensic-rag-mcp"
    $INSTALL_TRIAGE  && add_stdio_server "windows-triage" "windows_triage" "$INSTALL_DIR/windows-triage-mcp"
    $INSTALL_OPENCTI && add_stdio_server "opencti-mcp" "opencti_mcp" "$INSTALL_DIR/opencti-mcp"

    # Remote MCPs (zero-config)
    $INCLUDE_ZELTSER && add_http_server "zeltser-ir-writing" "https://website-mcp.zeltser.com/mcp"
    $INCLUDE_MSLEARN && add_http_server "microsoft-learn" "https://learn.microsoft.com/api/mcp"

    # Remote MCPs (with credentials)
    if $INSTALL_REMNUX && [[ -n "$REMNUX_HOST" ]]; then
        add_streamable_http_server "remnux-mcp" "http://$REMNUX_HOST:$REMNUX_PORT/mcp" "$REMNUX_TOKEN"
    fi

    local config="{\"mcpServers\":{$servers}}"

    mkdir -p "$(dirname "$output_file")"
    echo "$config" | $PYTHON -m json.tool > "$output_file"
    chmod 600 "$output_file"
    ok "Generated: $output_file"
}

case "$CLIENT_CHOICE" in
    1)
        CONFIG_DIR=$(prompt "Project directory for .mcp.json" "$(pwd)")
        generate_mcp_config "$CONFIG_DIR/.mcp.json"
        # Copy AGENTS.md as CLAUDE.md
        if [[ -f "$INSTALL_DIR/forensic-mcp/AGENTS.md" ]]; then
            cp "$INSTALL_DIR/forensic-mcp/AGENTS.md" "$CONFIG_DIR/CLAUDE.md"
            ok "Copied AGENTS.md → CLAUDE.md"
        fi
        ;;
    2)
        generate_mcp_config "$HOME/.config/claude/claude_desktop_config.json"
        ;;
    3)
        CONFIG_DIR=$(prompt "Project directory for .cursor/mcp.json" "$(pwd)")
        generate_mcp_config "$CONFIG_DIR/.cursor/mcp.json"
        # Copy AGENTS.md as .cursorrules
        if [[ -f "$INSTALL_DIR/forensic-mcp/AGENTS.md" ]]; then
            cp "$INSTALL_DIR/forensic-mcp/AGENTS.md" "$CONFIG_DIR/.cursorrules"
            ok "Copied AGENTS.md → .cursorrules"
        fi
        ;;
    4)
        echo ""
        echo "Add the following MCP server entries to your client configuration:"
        echo ""
        generate_mcp_config "/tmp/aiir-mcp-config.json"
        cat /tmp/aiir-mcp-config.json
        rm -f /tmp/aiir-mcp-config.json
        echo ""
        ;;
    5)
        info "Skipping client configuration. Run 'aiir setup' later."
        ;;
esac

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

        if $INSTALL_GATEWAY; then
            echo -e "${BOLD}Gateway:${NC}"
            echo "  The gateway allows remote MCPs (like wintools-mcp on Windows) to connect."
            echo "  Configure: $INSTALL_DIR/aiir-gateway/config/gateway.yaml"
            echo "  Start: cd $INSTALL_DIR/aiir-gateway && .venv/bin/aiir-gateway --config config/gateway.yaml"
            echo ""
        fi

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
# Summary
# =============================================================================

header "Installation Complete"

echo "Installed components:"
ok "forensic-mcp"
ok "aiir CLI"
$INSTALL_SIFT    && ok "sift-mcp"
$INSTALL_RAG     && ok "forensic-rag-mcp"
$INSTALL_TRIAGE  && ok "windows-triage-mcp"
$INSTALL_OPENCTI && ok "opencti-mcp"
$INSTALL_GATEWAY && ok "aiir-gateway"

echo ""
echo "Remote MCPs:"
$INCLUDE_ZELTSER && ok "zeltser-ir-writing (IR report writing)"
$INCLUDE_MSLEARN && ok "microsoft-learn (MS documentation)"
$INSTALL_REMNUX && [[ -n "$REMNUX_HOST" ]] && ok "remnux-mcp ($REMNUX_HOST:$REMNUX_PORT)"

echo ""
echo "Examiner: $EXAMINER"
echo "Install dir: $INSTALL_DIR"
echo ""

echo "Next steps:"
echo "  1. Restart your shell (or: source ${SHELL_RC:-~/.bashrc})"
echo "  2. Start your LLM client and begin an investigation"
echo "  3. Run: aiir setup test    — to verify all MCPs are working"
echo "  4. The AI should call init_case() to start a new case"

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
