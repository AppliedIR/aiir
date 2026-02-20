#!/usr/bin/env bash
#
# setup-sift.sh — AIIR Platform Installer for SIFT Workstation
#
# Installs selected MCP servers, configures your LLM client, and sets up
# examiner identity. Run this on a SIFT workstation (or any Linux system).
#
# Usage:
#   curl -sL https://raw.githubusercontent.com/AppliedIR/aiir/main/scripts/setup-sift.sh | bash
#   # or:
#   ./setup-sift.sh
#
set -euo pipefail

# --- Parse arguments ---
AUTO_YES=false
for arg in "$@"; do
    case "$arg" in
        -y|--yes) AUTO_YES=true ;;
    esac
done

# --- Colors and helpers ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; }
header() { echo -e "\n${BOLD}=== $* ===${NC}\n"; }

prompt() {
    local msg="$1" default="${2:-}"
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

# --- Banner ---
echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}  AIIR — Applied Incident Response Platform${NC}"
echo -e "${BOLD}  SIFT Workstation Installer${NC}"
echo -e "${BOLD}============================================================${NC}"
echo ""

# --- Phase 1: Prerequisites ---
header "Phase 1: Checking Prerequisites"

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
    OFFLINE=false
else
    warn "Cannot reach GitHub — some features may not work"
    OFFLINE=true
fi

# --- Phase 2: Select Components ---
header "Phase 2: Select Components"

echo "Which MCP servers would you like to install?"
echo ""
echo -e "  ${BOLD}Required (always installed):${NC}"
echo "    forensic-mcp      — Case management, findings, evidence, discipline"
echo "    aiir CLI           — Human review, approval, configuration"
echo ""
echo -e "  ${BOLD}Recommended:${NC}"
echo "    sift-mcp           — Forensic tool execution (SIFT workstation tools)"
echo "    forensic-rag-mcp   — Knowledge search (Sigma, MITRE, KAPE rules)"
echo "    windows-triage-mcp — Windows baseline validation (runs on Linux)"
echo ""
echo -e "  ${BOLD}Optional:${NC}"
echo "    opencti-mcp        — Threat intelligence (requires OpenCTI server)"
echo "    aiir-gateway       — HTTP gateway (for multi-machine / OpenWebUI)"
echo ""

INSTALL_SIFT=false
INSTALL_RAG=false
INSTALL_TRIAGE=false
INSTALL_OPENCTI=false
INSTALL_GATEWAY=false

if prompt_yn "Install all recommended components?" "y"; then
    INSTALL_SIFT=true
    INSTALL_RAG=true
    INSTALL_TRIAGE=true
else
    prompt_yn "  Install sift-mcp (forensic tools)?" "y" && INSTALL_SIFT=true
    prompt_yn "  Install forensic-rag-mcp (knowledge search)?" "y" && INSTALL_RAG=true
    prompt_yn "  Install windows-triage-mcp (Windows baseline)?" "y" && INSTALL_TRIAGE=true
fi

prompt_yn "Install opencti-mcp (threat intelligence)?" "n" && INSTALL_OPENCTI=true
prompt_yn "Install aiir-gateway (HTTP gateway)?" "n" && INSTALL_GATEWAY=true

# --- Phase 3: Install ---
header "Phase 3: Installing"

# Determine install directory
INSTALL_DIR=$(prompt "Installation directory" "$HOME/aiir")
INSTALL_DIR=$(realpath -m "$INSTALL_DIR")
mkdir -p "$INSTALL_DIR"
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
    module=$(echo "$repo" | sed 's/-mcp$//' | sed 's/-/_/g')
    # Handle special module names
    case "$name" in
        forensic-rag-mcp) module="rag_mcp" ;;
        windows-triage-mcp) module="windows_triage" ;;
        forensic-mcp) module="forensic_mcp" ;;
        forensic-knowledge) module="forensic_knowledge" ;;
        sift-mcp) module="sift_mcp" ;;
        opencti-mcp) module="opencti_mcp" ;;
        aiir-gateway) module="aiir_gateway" ;;
        aiir) module="aiir_cli" ;;
    esac

    if "$dir/.venv/bin/python" -c "import $module" 2>/dev/null; then
        ok "$name installed and importable"
    else
        warn "$name installed but import failed — check dependencies"
    fi
}

# forensic-knowledge is a dependency for forensic-mcp and sift-mcp
install_mcp "forensic-knowledge" "forensic-knowledge"

# Always install forensic-mcp and aiir CLI
install_mcp "forensic-mcp" "forensic-mcp" "dev"
install_mcp "aiir" "aiir" "dev"

# Install selected components
$INSTALL_SIFT && install_mcp "sift-mcp" "sift-mcp" "dev"
$INSTALL_RAG && install_mcp "forensic-rag-mcp" "forensic-rag-mcp"
$INSTALL_TRIAGE && install_mcp "windows-triage-mcp" "windows-triage-mcp"
$INSTALL_OPENCTI && install_mcp "opencti-mcp" "opencti-mcp"
$INSTALL_GATEWAY && install_mcp "aiir-gateway" "aiir-gateway" "dev"

# Add aiir CLI to PATH
AIIR_BIN="$INSTALL_DIR/aiir/.venv/bin"
if [[ ":$PATH:" != *":$AIIR_BIN:"* ]]; then
    info "Adding aiir to PATH..."
    SHELL_RC=""
    if [[ -f "$HOME/.bashrc" ]]; then SHELL_RC="$HOME/.bashrc";
    elif [[ -f "$HOME/.zshrc" ]]; then SHELL_RC="$HOME/.zshrc"; fi

    if [[ -n "$SHELL_RC" ]]; then
        if ! grep -q "aiir/.venv/bin" "$SHELL_RC" 2>/dev/null; then
            echo "" >> "$SHELL_RC"
            echo "# AIIR Platform" >> "$SHELL_RC"
            echo "export PATH=\"$AIIR_BIN:\$PATH\"" >> "$SHELL_RC"
            ok "Added to $SHELL_RC (restart shell or: source $SHELL_RC)"
        fi
    fi
    export PATH="$AIIR_BIN:$PATH"
fi

# --- Phase 4: Heavy MCP Setup ---
if $INSTALL_RAG; then
    header "Phase 4a: forensic-rag-mcp Index"
    echo "forensic-rag-mcp needs to build a search index (~2GB disk for ML model)."
    echo "Options:"
    echo "  1. Build now (downloads model, builds index — takes a few minutes)"
    echo "  2. Skip for now (build later with: cd $INSTALL_DIR/forensic-rag-mcp && .venv/bin/python -m rag_mcp.build)"
    echo ""
    if prompt_yn "Build index now?" "y"; then
        info "Building forensic-rag index (this may take a few minutes)..."
        (cd "$INSTALL_DIR/forensic-rag-mcp" && .venv/bin/python -m rag_mcp.build) && \
            ok "Index built" || warn "Index build failed — you can retry later"
    else
        info "Skipping index build. Remember to build before first use."
    fi
fi

if $INSTALL_TRIAGE; then
    header "Phase 4b: windows-triage-mcp Databases"
    echo "windows-triage-mcp needs Windows baseline databases."
    echo "These require cloning data repositories and running importers."
    echo ""
    echo "Options:"
    echo "  1. Set up now (clone repos + import — takes 30-60 minutes)"
    echo "  2. Skip for now (see $INSTALL_DIR/windows-triage-mcp/SETUP.md)"
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
        info "Skipping database setup. See SETUP.md for manual instructions."
    fi
fi

if $INSTALL_OPENCTI; then
    header "Phase 4c: OpenCTI Configuration"
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
        info "Skipping OpenCTI configuration. Set OPENCTI_URL and OPENCTI_TOKEN later."
        OPENCTI_URL=""
        OPENCTI_TOKEN=""
    fi
fi

# --- Phase 5: LLM Client Configuration ---
header "Phase 5: Configure LLM Client"

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

    add_server() {
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

    add_server "forensic-mcp" "forensic_mcp" "$INSTALL_DIR/forensic-mcp"
    $INSTALL_SIFT && add_server "sift-mcp" "sift_mcp" "$INSTALL_DIR/sift-mcp"
    $INSTALL_RAG && add_server "forensic-rag" "rag_mcp" "$INSTALL_DIR/forensic-rag-mcp"
    $INSTALL_TRIAGE && add_server "windows-triage" "windows_triage" "$INSTALL_DIR/windows-triage-mcp"
    $INSTALL_OPENCTI && add_server "opencti-mcp" "opencti_mcp" "$INSTALL_DIR/opencti-mcp"

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

# --- Phase 6: Examiner Identity ---
header "Phase 6: Examiner Identity"

echo "Your examiner name identifies your work in case files and audit trails."
echo "Use a short slug (e.g., steve, jane, analyst1)."
echo ""
EXAMINER=$(prompt "Examiner name" "$(whoami)")
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

# --- Phase 7: Team Deployment (optional) ---
echo ""
if prompt_yn "Set up for team collaboration?" "n"; then
    header "Phase 7: Team Deployment"

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
    echo "    [$( basename "$CASE_DIR" )]"
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

# --- Summary ---
header "Installation Complete"

echo "Installed components:"
ok "forensic-mcp"
ok "aiir CLI"
$INSTALL_SIFT && ok "sift-mcp"
$INSTALL_RAG && ok "forensic-rag-mcp"
$INSTALL_TRIAGE && ok "windows-triage-mcp"
$INSTALL_OPENCTI && ok "opencti-mcp"
$INSTALL_GATEWAY && ok "aiir-gateway"
echo ""
echo "Examiner: $EXAMINER"
echo "Install dir: $INSTALL_DIR"
echo ""
echo "Next steps:"
echo "  1. Restart your shell (or: source ${SHELL_RC:-~/.bashrc})"
echo "  2. Start your LLM client and begin an investigation"
echo "  3. Run: aiir setup test    — to verify all MCPs are working"
echo "  4. The AI should call init_case() to start a new case"
echo ""
echo -e "${BOLD}Documentation:${NC} $INSTALL_DIR/forensic-mcp/AGENTS.md"
echo ""
