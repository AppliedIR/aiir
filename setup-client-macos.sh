#!/usr/bin/env bash
#
# setup-client-macos.sh — AIIR LLM Client Setup for macOS
#
# Joins the SIFT gateway and produces a reference MCP config file.
# Lightweight — no Python, no git, no venv required.
#
# Usage:
#   ./setup-client-macos.sh --sift=https://IP:4508 --code=XXXX-XXXX
#   ./setup-client-macos.sh -h
#
set -euo pipefail

# =============================================================================
# Parse Arguments
# =============================================================================

SIFT_URL=""
JOIN_CODE=""

for arg in "$@"; do
    case "$arg" in
        --sift=*)  SIFT_URL="${arg#*=}" ;;
        --code=*)  JOIN_CODE="${arg#*=}" ;;
        -h|--help)
            echo "Usage: setup-client-macos.sh --sift=URL --code=CODE"
            echo ""
            echo "Options:"
            echo "  --sift=URL     Gateway URL (required)"
            echo "  --code=CODE    Join code (required)"
            echo "  -h, --help     Show this help"
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

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

info()   { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()     { echo -e "${GREEN}[OK]${NC} $*"; }
warn()   { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()    { echo -e "${RED}[ERROR]${NC} $*"; }

# =============================================================================
# Banner
# =============================================================================

echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}  AIIR — LLM Client Setup (macOS)${NC}"
echo -e "${BOLD}  Artificial Intelligence Incident Response${NC}"
echo -e "${BOLD}============================================================${NC}"
echo ""

# =============================================================================
# Validate
# =============================================================================

if [[ -z "$SIFT_URL" ]]; then
    err "Gateway URL is required: --sift=https://IP:4508"
    exit 1
fi
if [[ -z "$JOIN_CODE" ]]; then
    err "Join code is required: --code=XXXX-XXXX"
    exit 1
fi

SIFT_URL="${SIFT_URL%/}"

# =============================================================================
# Join Gateway
# =============================================================================

info "Joining gateway at $SIFT_URL..."

CURL_OPTS=(-sS --max-time 30)
if [[ "$SIFT_URL" == https* ]]; then
    if [[ -f "$HOME/.aiir/tls/ca-cert.pem" ]]; then
        CURL_OPTS+=(--cacert "$HOME/.aiir/tls/ca-cert.pem")
    else
        CURL_OPTS+=(-k)
        warn "Using insecure TLS (no CA cert found)."
    fi
fi

# Sanitize inputs for JSON interpolation
if [[ ! "$JOIN_CODE" =~ ^[A-Za-z0-9_-]+$ ]]; then
    err "Invalid join code format (alphanumeric, dash, underscore only)"
    exit 1
fi
HOSTNAME_VAL=$(hostname 2>/dev/null || echo "unknown")
HOSTNAME_VAL=$(echo "$HOSTNAME_VAL" | tr -cd 'A-Za-z0-9._-')

JOIN_RESPONSE=$(curl "${CURL_OPTS[@]}" -X POST "$SIFT_URL/api/v1/setup/join" \
    -H "Content-Type: application/json" \
    -d "{\"code\":\"$JOIN_CODE\",\"machine_type\":\"examiner\",\"hostname\":\"$HOSTNAME_VAL\"}" 2>&1) || {
    err "Failed to connect to gateway at $SIFT_URL"
    exit 1
}

# Check for error
if echo "$JOIN_RESPONSE" | grep -q '"error"'; then
    ERROR_MSG=$(echo "$JOIN_RESPONSE" | sed 's/.*"error"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
    err "Join failed: $ERROR_MSG"
    exit 1
fi

if ! echo "$JOIN_RESPONSE" | grep -q '"gateway_token"'; then
    err "Unexpected response from gateway"
    exit 1
fi

GATEWAY_TOKEN=$(echo "$JOIN_RESPONSE" | sed 's/.*"gateway_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
GATEWAY_URL=$(echo "$JOIN_RESPONSE" | sed 's/.*"gateway_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
BACKENDS_RAW=$(echo "$JOIN_RESPONSE" | sed 's/.*"backends"[[:space:]]*:[[:space:]]*\[\([^]]*\)\].*/\1/')
BACKENDS=$(echo "$BACKENDS_RAW" | tr ',' '\n' | sed 's/[[:space:]]*"//g')

if [[ -z "$GATEWAY_URL" ]] || [[ "$GATEWAY_URL" == "$JOIN_RESPONSE" ]]; then
    GATEWAY_URL="$SIFT_URL"
fi

ok "Joined gateway"

# Store token
mkdir -p "$HOME/.aiir" && chmod 700 "$HOME/.aiir"
cat > "$HOME/.aiir/config.yaml" << CONF
gateway_url: "$GATEWAY_URL"
gateway_token: "$GATEWAY_TOKEN"
CONF
chmod 600 "$HOME/.aiir/config.yaml"

# =============================================================================
# Reference Config
# =============================================================================

CONFIG_FILE="$HOME/.aiir/mcp-config.txt"

{
    echo "# AIIR MCP Configuration Reference"
    echo "# Generated $(date -u '+%Y-%m-%d %H:%M UTC')"
    echo "#"
    echo "# Configure each MCP server below in your LLM client."
    echo "# All connections use Streamable HTTP with bearer token auth."
    echo ""
    echo "# --- SIFT Gateway Backends ---"
    echo ""

    while IFS= read -r backend; do
        [[ -z "$backend" ]] && continue
        echo "Name:    $backend"
        echo "Type:    streamable-http"
        echo "URL:     $GATEWAY_URL/mcp/$backend"
        echo "Header:  Authorization: Bearer $GATEWAY_TOKEN"
        echo ""
    done <<< "$BACKENDS"

    echo "# --- External MCPs ---"
    echo ""
    echo "Name:    zeltser-ir-writing (required for reporting)"
    echo "Type:    streamable-http"
    echo "URL:     https://website-mcp.zeltser.com/mcp"
    echo ""
    echo "Name:    ms-learn (optional)"
    echo "Type:    streamable-http"
    echo "URL:     https://learn.microsoft.com/api/mcp"
    echo ""
    echo "Name:    remnux (optional, if you have a REMnux VM)"
    echo "Type:    streamable-http"
    echo "URL:     http://REMNUX_IP:8080/mcp"
    echo ""
    echo "# Configure the above MCPs in your LLM client per your"
    echo "# client's documentation."
} > "$CONFIG_FILE"

ok "Reference config written: $CONFIG_FILE"

# =============================================================================
# Advisories
# =============================================================================

echo ""
echo -e "${BOLD}SSH Access${NC}"
echo "  SSH access to SIFT is required for finding approval and rejection"
echo "  (aiir approve, aiir reject), evidence unlocking (aiir evidence"
echo "  unlock), and command execution (aiir execute). These operations"
echo "  require PIN or terminal confirmation and are not available through"
echo "  MCP. All other operations are available through MCP tools."

echo ""
echo -e "${YELLOW}${BOLD}IMPORTANT: Terminal-Access LLM Clients${NC}"
echo "  If you use Claude Code or another LLM client with terminal access,"
echo "  the LLM can use your SSH credentials to run commands directly on"
echo "  SIFT, bypassing MCP audit controls and forensic integrity features."
echo "  We recommend MCP-only clients (Claude Desktop, LibreChat) which can"
echo "  only interact with SIFT through audited MCP tools."
echo ""
echo "  If you choose to use a terminal-access LLM, ensure your SSH"
echo "  authentication to SIFT requires human interaction per use (password"
echo "  auth, ssh-add -c, or hardware security keys) so the LLM cannot"
echo "  authenticate automatically."

echo ""
echo -e "${BOLD}Documentation:${NC} https://appliedir.github.io/aiir/"
echo ""
