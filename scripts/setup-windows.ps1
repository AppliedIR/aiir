#Requires -Version 5.1
<#
.SYNOPSIS
    AIIR Platform Installer for Windows Forensic Workstation

.DESCRIPTION
    Installs wintools-mcp, scans for forensic tools, generates a tool
    inventory report, starts the MCP server, and configures auto-start.

    Run this on a Windows forensic workstation where Zimmerman tools,
    Hayabusa, Sysinternals, etc. are installed.

.EXAMPLE
    # Interactive install
    .\setup-windows.ps1

    # Non-interactive with defaults
    .\setup-windows.ps1 -NonInteractive

    # Custom install directory and port
    .\setup-windows.ps1 -InstallDir "D:\AIIR" -Port 4624
#>
[CmdletBinding()]
param(
    [switch]$NonInteractive,
    [string]$InstallDir = "",
    [string]$Examiner = "",
    [int]$Port = 4624,
    [string]$Host = "0.0.0.0"
)

$ErrorActionPreference = "Stop"

# =============================================================================
# Helpers
# =============================================================================

function Write-Info   { param($msg) Write-Host "[INFO] " -ForegroundColor Blue -NoNewline; Write-Host $msg }
function Write-Ok     { param($msg) Write-Host "[OK] " -ForegroundColor Green -NoNewline; Write-Host $msg }
function Write-Warn   { param($msg) Write-Host "[WARN] " -ForegroundColor Yellow -NoNewline; Write-Host $msg }
function Write-Err    { param($msg) Write-Host "[ERROR] " -ForegroundColor Red -NoNewline; Write-Host $msg }
function Write-Header { param($msg) Write-Host "`n=== $msg ===`n" -ForegroundColor White }

function Read-Prompt {
    param([string]$Message, [string]$Default = "")
    if ($NonInteractive) { return $Default }
    if ($Default) {
        $answer = Read-Host "$Message [$Default]"
        if ([string]::IsNullOrWhiteSpace($answer)) { return $Default }
        return $answer
    }
    return Read-Host $Message
}

function Read-YesNo {
    param([string]$Message, [bool]$Default = $true)
    if ($NonInteractive) { return $Default }
    $suffix = if ($Default) { "[Y/n]" } else { "[y/N]" }
    $answer = Read-Host "$Message $suffix"
    if ([string]::IsNullOrWhiteSpace($answer)) { return $Default }
    return $answer.ToLower().StartsWith("y")
}

# =============================================================================
# Banner
# =============================================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Host "  AIIR - Applied Incident Response Platform" -ForegroundColor White
Write-Host "  Windows Workstation Installer" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host ""

# =============================================================================
# Prerequisites
# =============================================================================

Write-Header "Checking Prerequisites"

# Python 3.10+
$pythonCmd = $null
foreach ($cmd in @("python", "python3", "py -3")) {
    try {
        $ver = & ($cmd.Split(" ")[0]) @($cmd.Split(" ") | Select-Object -Skip 1) -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
        if ($ver) {
            $parts = $ver.Split(".")
            $major = [int]$parts[0]
            $minor = [int]$parts[1]
            if ($major -ge 3 -and $minor -ge 10) {
                $pythonCmd = $cmd
                Write-Ok "Python $ver"
                break
            }
        }
    } catch { }
}

if (-not $pythonCmd) {
    Write-Err "Python 3.10+ not found"
    Write-Host "  Install from: https://www.python.org/downloads/"
    Write-Host "  Or via winget: winget install Python.Python.3.12"
    exit 1
}

# pip
try {
    & ($pythonCmd.Split(" ")[0]) @($pythonCmd.Split(" ") | Select-Object -Skip 1) -m pip --version 2>$null | Out-Null
    Write-Ok "pip available"
} catch {
    Write-Err "pip not found"
    Write-Host "  Run: $pythonCmd -m ensurepip --upgrade"
    exit 1
}

# git
if (Get-Command git -ErrorAction SilentlyContinue) {
    $gitVer = (git --version) -replace "git version ", ""
    Write-Ok "git $gitVer"
} else {
    Write-Err "git not found"
    Write-Host "  Install from: https://git-scm.com/download/win"
    Write-Host "  Or via winget: winget install Git.Git"
    exit 1
}

# .NET Runtime (for Zimmerman tools)
$hasDotnet = $false
if (Get-Command dotnet -ErrorAction SilentlyContinue) {
    $dotnetVer = (dotnet --version 2>$null)
    if ($dotnetVer) {
        Write-Ok ".NET $dotnetVer"
        $hasDotnet = $true
    }
}
if (-not $hasDotnet) {
    Write-Warn ".NET Runtime not found (needed for Zimmerman tools)"
    Write-Host "  Install from: https://dotnet.microsoft.com/download"
    Write-Host "  Or via winget: winget install Microsoft.DotNet.Runtime.8"
}

# Network
try {
    git ls-remote https://github.com/AppliedIR/aiir.git HEAD 2>$null | Out-Null
    Write-Ok "Network access to GitHub"
} catch {
    Write-Warn "Cannot reach GitHub - installation requires network access"
    exit 1
}

# =============================================================================
# Install
# =============================================================================

Write-Header "Installing wintools-mcp"

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    $defaultDir = "C:\Tools\aiir"
    if (-not (Test-Path "C:\Tools")) {
        $defaultDir = "$env:USERPROFILE\aiir"
    }
    $InstallDir = Read-Prompt "Installation directory" $defaultDir
}

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}
Write-Info "Installing to $InstallDir"

$githubOrg = "https://github.com/AppliedIR"
$wintoolsDir = Join-Path $InstallDir "wintools-mcp"

# Clone or update
if (Test-Path $wintoolsDir) {
    Write-Info "Directory exists, pulling latest..."
    Push-Location $wintoolsDir
    try { git pull --quiet 2>$null } catch { Write-Warn "Could not update (network issue?)" }
    Pop-Location
} else {
    git clone --quiet "$githubOrg/wintools-mcp.git" $wintoolsDir
}

# Create venv and install
$venvDir = Join-Path $wintoolsDir ".venv"
$venvPython = Join-Path $venvDir "Scripts\python.exe"

if (-not (Test-Path $venvDir)) {
    & ($pythonCmd.Split(" ")[0]) @($pythonCmd.Split(" ") | Select-Object -Skip 1) -m venv $venvDir
}

& $venvPython -m pip install --quiet --upgrade pip 2>$null
& $venvPython -m pip install --quiet -e "$wintoolsDir[fk,dev]"

# Smoke test
try {
    $result = & $venvPython -c "import wintools_mcp; print('ok')" 2>$null
    if ($result -eq "ok") {
        Write-Ok "wintools-mcp installed and importable"
    } else {
        Write-Warn "wintools-mcp installed but import failed - check dependencies"
    }
} catch {
    Write-Warn "wintools-mcp installed but import failed - check dependencies"
}

# =============================================================================
# Examiner Identity
# =============================================================================

Write-Header "Examiner Identity"

Write-Host "Your examiner name identifies your work in audit trails."
Write-Host "Use a short slug (e.g., steve, jane, analyst1)."
Write-Host ""

if ([string]::IsNullOrWhiteSpace($Examiner)) {
    $defaultExaminer = $env:USERNAME.ToLower() -replace "[^a-z0-9-]", ""
    $Examiner = Read-Prompt "Examiner name" $defaultExaminer
}
$Examiner = $Examiner.ToLower() -replace "[^a-z0-9-]", ""
if ([string]::IsNullOrWhiteSpace($Examiner)) {
    $Examiner = $env:USERNAME.ToLower() -replace "[^a-z0-9-]", ""
}

# Save config
$aiirConfigDir = Join-Path $env:USERPROFILE ".aiir"
if (-not (Test-Path $aiirConfigDir)) {
    New-Item -ItemType Directory -Path $aiirConfigDir -Force | Out-Null
}
"examiner: $Examiner" | Set-Content -Path (Join-Path $aiirConfigDir "config.yaml") -Encoding UTF8
Write-Ok "Saved examiner identity: $Examiner"

# Set env var persistently
[Environment]::SetEnvironmentVariable("AIIR_EXAMINER", $Examiner, "User")
$env:AIIR_EXAMINER = $Examiner
Write-Ok "Set AIIR_EXAMINER=$Examiner"

# =============================================================================
# Tool Inventory
# =============================================================================

Write-Header "Scanning for Forensic Tools"

# Run scan and capture output
$scanOutput = & $venvPython -m wintools_mcp --scan 2>$null

if ($scanOutput) {
    Write-Host $($scanOutput -join "`n")
} else {
    Write-Warn "Tool scan could not run"
}

# Generate TOOLS_OVERVIEW.md
Write-Host ""
Write-Info "Generating tool inventory report..."

$overviewPath = Join-Path $InstallDir "TOOLS_OVERVIEW.md"
$overviewContent = & $venvPython -c @"
import json
from datetime import datetime
from wintools_mcp.catalog import load_catalog
from wintools_mcp.environment import find_binary

catalog = load_catalog()
found = []
missing = []
for name, td in sorted(catalog.items()):
    path = find_binary(td.binary)
    if path:
        found.append((td.name, td.category, td.binary, path))
    else:
        missing.append((td.name, td.category, td.description or ''))

lines = []
lines.append(f'# AIIR Tool Inventory - {datetime.now().strftime("%Y-%m-%d %H:%M")}')
lines.append('')
lines.append(f'Generated by setup-windows.ps1 on {datetime.now().strftime("%Y-%m-%d")}.')
lines.append(f'wintools-mcp rescans automatically on each discovery call.')
lines.append('')
lines.append(f'## Installed ({len(found)}/{len(found)+len(missing)})')
lines.append('')
if found:
    lines.append('| Tool | Category | Path |')
    lines.append('|------|----------|------|')
    for name, cat, binary, path in found:
        lines.append(f'| {name} | {cat} | {path} |')
else:
    lines.append('No tools found.')
lines.append('')
lines.append(f'## Missing ({len(missing)}/{len(found)+len(missing)})')
lines.append('')
if missing:
    lines.append('| Tool | Category | Description |')
    lines.append('|------|----------|-------------|')
    for name, cat, desc in missing:
        lines.append(f'| {name} | {cat} | {desc} |')
else:
    lines.append('All catalog tools are installed.')
lines.append('')
lines.append('## Notes')
lines.append('')
lines.append('- Install missing tools and restart wintools-mcp (or call scan_tools via MCP)')
lines.append('- wintools-mcp checks tool availability dynamically on each discovery call')
lines.append('- Common tool sources:')
lines.append('  - Zimmerman Suite: https://ericzimmerman.github.io/')
lines.append('  - Hayabusa: https://github.com/Yamato-Security/hayabusa/releases')
lines.append('  - Sysinternals: winget install Microsoft.Sysinternals')
lines.append('')
print('\n'.join(lines))
"@ 2>$null

if ($overviewContent) {
    $overviewContent -join "`n" | Set-Content -Path $overviewPath -Encoding UTF8
    Write-Ok "Generated: $overviewPath"
} else {
    Write-Warn "Could not generate TOOLS_OVERVIEW.md"
}

# =============================================================================
# Start MCP Server
# =============================================================================

Write-Header "Starting wintools-mcp"

Write-Info "Starting wintools-mcp on port $Port..."

# Start in background to validate it works
$startArgs = @("-m", "wintools_mcp", "--http", "--host", $Host, "--port", "$Port")
$process = Start-Process -FilePath $venvPython -ArgumentList $startArgs -PassThru -WindowStyle Hidden -Environment @{ AIIR_EXAMINER = $Examiner }

Start-Sleep -Seconds 3

# Check if it's running
if (-not $process.HasExited) {
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:$Port/health" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
        Write-Ok "wintools-mcp running on port $Port"
    } catch {
        Write-Warn "wintools-mcp started but health check failed"
    }
} else {
    Write-Warn "wintools-mcp exited immediately - check configuration"
}

# =============================================================================
# Auto-Start Configuration
# =============================================================================

Write-Header "Startup Configuration"

Write-Host "wintools-mcp is running now. How should it start in the future?"
Write-Host ""
Write-Host "  1. Auto-start at boot (scheduled task)"
Write-Host "  2. Manual start (generates start-wintools.ps1)"
Write-Host ""

$startChoice = Read-Prompt "Choose" "1"

# Always generate the startup script (useful either way)
$startupPath = Join-Path $InstallDir "start-wintools.ps1"
@"
# Start wintools-mcp in HTTP mode
`$env:AIIR_EXAMINER = "$Examiner"
& "$venvPython" -m wintools_mcp --http --host $Host --port $Port
"@ | Set-Content -Path $startupPath -Encoding UTF8

if ($startChoice -eq "1") {
    # Register scheduled task for auto-start
    $taskName = "AIIR wintools-mcp"

    try {
        # Remove existing task if present
        $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($existing) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            Write-Info "Removed existing scheduled task"
        }

        $action = New-ScheduledTaskAction `
            -Execute $venvPython `
            -Argument "-m wintools_mcp --http --host $Host --port $Port"
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $settings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -StartWhenAvailable `
            -RestartCount 3 `
            -RestartInterval (New-TimeSpan -Minutes 1)

        Register-ScheduledTask `
            -TaskName $taskName `
            -Action $action `
            -Trigger $trigger `
            -Settings $settings `
            -RunLevel Highest `
            -User "SYSTEM" `
            -Description "AIIR wintools-mcp forensic tool server" | Out-Null

        Write-Ok "Scheduled task registered: $taskName"
        Write-Ok "Will auto-start at boot"
    } catch {
        Write-Warn "Could not register scheduled task (run as Administrator)"
        Write-Host "  To register manually (as Administrator):"
        Write-Host "  schtasks /create /tn `"$taskName`" /tr `"$venvPython -m wintools_mcp --http --host $Host --port $Port`" /sc onstart /ru SYSTEM"
        Write-Host ""
        Write-Host "  Or use the startup script: $startupPath"
    }

    # Add firewall rule
    try {
        $ruleName = "AIIR wintools-mcp"
        $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if (-not $existingRule) {
            New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow | Out-Null
            Write-Ok "Firewall rule added for TCP port $Port"
        } else {
            Write-Ok "Firewall rule already exists"
        }
    } catch {
        Write-Warn "Could not add firewall rule (run as Administrator)"
        Write-Host "  Manual: netsh advfirewall firewall add rule name=`"AIIR wintools-mcp`" dir=in action=allow protocol=TCP localport=$Port"
    }
} else {
    Write-Ok "Generated startup script: $startupPath"
    Write-Host "  Run it to start wintools-mcp: $startupPath"
}

# =============================================================================
# Audit Trail Warning
# =============================================================================

Write-Header "IMPORTANT: Case Directory Access"

Write-Host "============================================================" -ForegroundColor Yellow
Write-Host "  WARNING: Audit trail requires access to the case directory" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "  wintools-mcp writes forensic audit entries to the case" -ForegroundColor Yellow
Write-Host "  directory on your SIFT workstation. Without this, tool" -ForegroundColor Yellow
Write-Host "  executions on Windows are NOT recorded in the audit trail." -ForegroundColor Yellow
Write-Host ""
Write-Host "  To enable:" -ForegroundColor White
Write-Host "  1. Share the SIFT cases directory via SMB:"
Write-Host "     (on SIFT) sudo net usershare add cases /path/to/cases"
Write-Host ""
Write-Host "  2. Map the share on this Windows machine:"
Write-Host "     net use Z: \\SIFT_IP\cases"
Write-Host ""
Write-Host "  3. Set AIIR_CASE_DIR when starting a case:"
Write-Host "     set AIIR_CASE_DIR=Z:\INC-2026-0001"
Write-Host ""
Write-Host "  Without this, wintools-mcp still works but produces no"
Write-Host "  audit trail -- evidence IDs are generated but not logged." -ForegroundColor Yellow
Write-Host ""

# =============================================================================
# Summary
# =============================================================================

Write-Header "Installation Complete"

Write-Ok "wintools-mcp installed and running"
Write-Host ""
Write-Host "Examiner:       $Examiner"
Write-Host "Install dir:    $InstallDir"
Write-Host "HTTP server:    http://localhost:$Port"
Write-Host "Tool inventory: $overviewPath"
Write-Host ""

# Detect local IP for gateway config
$localIp = $null
try {
    $localIp = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "Loopback*" -and $_.PrefixOrigin -ne "WellKnown" } | Select-Object -First 1).IPAddress
} catch { }
if (-not $localIp) { $localIp = "THIS_MACHINE_IP" }

Write-Host "Add to your SIFT gateway.yaml:" -ForegroundColor White
Write-Host "  backends:"
Write-Host "    wintools-mcp:"
Write-Host "      type: http"
Write-Host "      url: `"http://${localIp}:${Port}/mcp`""
Write-Host "      enabled: true"
Write-Host ""

if ($startChoice -eq "1") {
    Write-Host "Auto-start: enabled (scheduled task)" -ForegroundColor Green
} else {
    Write-Host "Manual start: $startupPath" -ForegroundColor Yellow
}
Write-Host ""
