#Requires -Version 5.1
<#
.SYNOPSIS
    AIIR LLM Client Setup for Windows

.DESCRIPTION
    Joins the SIFT gateway and produces a reference MCP config file.
    Lightweight — no Python, no git required.

.PARAMETER Sift
    Gateway URL (required). Example: https://192.168.1.100:4508

.PARAMETER Code
    Join code (required). Generated on SIFT with: aiir setup join-code

.PARAMETER Help
    Show help and exit.

.EXAMPLE
    .\setup-client-windows.ps1 -Sift https://192.168.1.100:4508 -Code XXXX-XXXX
#>
param(
    [string]$Sift,
    [string]$Code,
    [switch]$Help
)

# =============================================================================
# Helpers
# =============================================================================

function Write-Info  { param([string]$Msg) Write-Host "[INFO] $Msg" -ForegroundColor Blue }
function Write-Ok    { param([string]$Msg) Write-Host "[OK] $Msg" -ForegroundColor Green }
function Write-Warn  { param([string]$Msg) Write-Host "[WARN] $Msg" -ForegroundColor Yellow }
function Write-Err   { param([string]$Msg) Write-Host "[ERROR] $Msg" -ForegroundColor Red }

# =============================================================================
# Banner + Help
# =============================================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Host "  AIIR - LLM Client Setup (Windows)" -ForegroundColor White
Write-Host "  Artificial Intelligence Incident Response" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host ""

if ($Help) {
    Write-Host "Usage: .\setup-client-windows.ps1 -Sift URL -Code CODE"
    Write-Host ""
    Write-Host "Parameters:"
    Write-Host "  -Sift URL     Gateway URL (required)"
    Write-Host "  -Code CODE    Join code (required)"
    Write-Host "  -Help         Show this help"
    exit 0
}

# =============================================================================
# Validate
# =============================================================================

if (-not $Sift) {
    Write-Err "Gateway URL is required: -Sift https://IP:4508"
    exit 1
}
if (-not $Code) {
    Write-Err "Join code is required: -Code XXXX-XXXX"
    exit 1
}

$Sift = $Sift.TrimEnd('/')

# =============================================================================
# Join Gateway
# =============================================================================

Write-Info "Joining gateway at $Sift..."

$hostname = [System.Net.Dns]::GetHostName()
$body = @{
    code = $Code
    machine_type = "examiner"
    hostname = $hostname
} | ConvertTo-Json

try {
    # Allow self-signed certs
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $response = Invoke-WebRequest -Uri "$Sift/api/v1/setup/join" `
            -Method Post -ContentType "application/json" -Body $body `
            -SkipCertificateCheck -UseBasicParsing
    } else {
        # PowerShell 5.1 — bypass cert validation
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        $response = Invoke-WebRequest -Uri "$Sift/api/v1/setup/join" `
            -Method Post -ContentType "application/json" -Body $body `
            -UseBasicParsing
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    }
} catch {
    Write-Err "Failed to connect to gateway at $Sift"
    Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

$json = $response.Content | ConvertFrom-Json

if ($json.error) {
    Write-Err "Join failed: $($json.error)"
    exit 1
}

if (-not $json.gateway_token) {
    Write-Err "Unexpected response from gateway"
    exit 1
}

$gatewayToken = $json.gateway_token
$gatewayUrl = if ($json.gateway_url) { $json.gateway_url } else { $Sift }
$backends = $json.backends

Write-Ok "Joined gateway"

# Store token
$aiirDir = Join-Path $HOME ".aiir"
if (-not (Test-Path $aiirDir)) {
    New-Item -ItemType Directory -Path $aiirDir -Force | Out-Null
}

$configFile = Join-Path $aiirDir "config.yaml"
@"
gateway_url: $gatewayUrl
gateway_token: $gatewayToken
"@ | Set-Content -Path $configFile -Encoding UTF8

Write-Ok "Credentials saved to $configFile"

# =============================================================================
# Reference Config
# =============================================================================

$mcpConfigFile = Join-Path $aiirDir "mcp-config.txt"
$timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm UTC")

$lines = @()
$lines += "# AIIR MCP Configuration Reference"
$lines += "# Generated $timestamp"
$lines += "#"
$lines += "# Configure each MCP server below in your LLM client."
$lines += "# All connections use Streamable HTTP with bearer token auth."
$lines += ""
$lines += "# --- SIFT Gateway Backends ---"
$lines += ""

foreach ($backend in $backends) {
    $lines += "Name:    $backend"
    $lines += "Type:    streamable-http"
    $lines += "URL:     $gatewayUrl/mcp/$backend"
    $lines += "Header:  Authorization: Bearer $gatewayToken"
    $lines += ""
}

$lines += "# --- External MCPs ---"
$lines += ""
$lines += "Name:    zeltser-ir-writing (required for reporting)"
$lines += "Type:    streamable-http"
$lines += "URL:     https://website-mcp.zeltser.com/mcp"
$lines += ""
$lines += "Name:    ms-learn (optional)"
$lines += "Type:    streamable-http"
$lines += "URL:     https://learn.microsoft.com/api/mcp"
$lines += ""
$lines += "Name:    remnux (optional, if you have a REMnux VM)"
$lines += "Type:    streamable-http"
$lines += "URL:     http://REMNUX_IP:8080/mcp"
$lines += ""
$lines += "# Configure the above MCPs in your LLM client per your"
$lines += "# client's documentation."

$lines -join "`n" | Set-Content -Path $mcpConfigFile -Encoding UTF8

Write-Ok "Reference config written: $mcpConfigFile"

# =============================================================================
# Advisories
# =============================================================================

Write-Host ""
Write-Host "SSH Access" -ForegroundColor White
Write-Host "  SSH access to SIFT is required for finding approval and rejection"
Write-Host "  (aiir approve, aiir reject), evidence unlocking (aiir evidence"
Write-Host "  unlock), and command execution (aiir execute). These operations"
Write-Host "  require PIN or terminal confirmation and are not available through"
Write-Host "  MCP. All other operations are available through MCP tools."
Write-Host ""
Write-Host "  Windows SSH clients: OpenSSH (built-in), PuTTY, or Windows Terminal."
Write-Host "  If using ssh-agent or pageant, configure per-use confirmation to"
Write-Host "  prevent automated key access."

Write-Host ""
Write-Host "IMPORTANT: Terminal-Access LLM Clients" -ForegroundColor Yellow
Write-Host "  If you use Claude Code or another LLM client with terminal access,"
Write-Host "  the LLM can use your SSH credentials to run commands directly on"
Write-Host "  SIFT, bypassing MCP audit controls and forensic integrity features."
Write-Host "  We recommend MCP-only clients (Claude Desktop, LibreChat) which can"
Write-Host "  only interact with SIFT through audited MCP tools."
Write-Host ""
Write-Host "  If you choose to use a terminal-access LLM, ensure your SSH"
Write-Host "  authentication to SIFT requires human interaction per use (password"
Write-Host "  auth, ssh-agent confirmation, or hardware security keys) so the LLM"
Write-Host "  cannot authenticate automatically."

Write-Host ""
Write-Host "Documentation: https://appliedir.github.io/aiir/" -ForegroundColor White
Write-Host ""
