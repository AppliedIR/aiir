#Requires -Version 5.1
<#
.SYNOPSIS
    AIIR Platform Installer for Windows Forensic Workstation

.DESCRIPTION
    Installs wintools-mcp and optionally the aiir CLI, scans for forensic
    tools, configures your LLM client, and sets up examiner identity.

    Run this on a Windows forensic workstation where Zimmerman tools,
    Hayabusa, Sysinternals, etc. are installed.

.EXAMPLE
    # Interactive install
    .\setup-windows.ps1

    # Non-interactive with defaults
    .\setup-windows.ps1 -NonInteractive
#>
[CmdletBinding()]
param(
    [switch]$NonInteractive,
    [string]$InstallDir = "",
    [string]$Examiner = ""
)

$ErrorActionPreference = "Stop"

# --- Colors and helpers ---
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

# --- Banner ---
Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Host "  AIIR - Applied Incident Response Platform" -ForegroundColor White
Write-Host "  Windows Workstation Installer" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host ""

# --- Phase 1: Prerequisites ---
Write-Header "Phase 1: Checking Prerequisites"

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
    Write-Host "  Or via choco:  choco install python312"
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
    $offline = $false
} catch {
    Write-Warn "Cannot reach GitHub - some features may not work"
    $offline = $true
}

# --- Phase 2: Select Components ---
Write-Header "Phase 2: Select Components"

Write-Host "Which components would you like to install?"
Write-Host ""
Write-Host "  Required:" -ForegroundColor White
Write-Host "    wintools-mcp      - Windows forensic tool execution"
Write-Host ""
Write-Host "  Recommended:" -ForegroundColor White
Write-Host "    aiir CLI          - Human review, approval, configuration"
Write-Host "    forensic-knowledge - Artifact/tool metadata (auto-installed)"
Write-Host ""
Write-Host "  Optional:" -ForegroundColor White
Write-Host "    forensic-mcp      - Case management (usually on SIFT side)"
Write-Host ""

$installAiir = Read-YesNo "Install aiir CLI (for local review/approval)?" $true
$installForensic = Read-YesNo "Install forensic-mcp (usually only needed on SIFT)?" $false

# --- Phase 3: Install ---
Write-Header "Phase 3: Installing"

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

function Install-MCP {
    param(
        [string]$Name,
        [string]$Repo,
        [string]$Extras = "",
        [string]$Module = ""
    )

    Write-Host ""
    Write-Info "Installing $Name..."

    $dir = Join-Path $InstallDir $Name

    if (Test-Path $dir) {
        Write-Info "  Directory exists, pulling latest..."
        Push-Location $dir
        git pull --quiet 2>$null
        Pop-Location
    } else {
        git clone --quiet "$githubOrg/$Repo.git" $dir
    }

    $venvDir = Join-Path $dir ".venv"
    $venvPython = Join-Path $venvDir "Scripts\python.exe"

    if (-not (Test-Path $venvDir)) {
        & ($pythonCmd.Split(" ")[0]) @($pythonCmd.Split(" ") | Select-Object -Skip 1) -m venv $venvDir
    }

    & $venvPython -m pip install --quiet --upgrade pip 2>$null

    if ($Extras) {
        & $venvPython -m pip install --quiet -e "$dir[$Extras]"
    } else {
        & $venvPython -m pip install --quiet -e $dir
    }

    # Determine module name
    if (-not $Module) {
        $Module = switch ($Name) {
            "wintools-mcp"  { "wintools_mcp" }
            "forensic-mcp"  { "forensic_mcp" }
            "aiir"          { "aiir_cli" }
            default         { $Repo -replace "-mcp$","" -replace "-","_" }
        }
    }

    # Smoke test
    try {
        $result = & $venvPython -c "import $Module; print('ok')" 2>$null
        if ($result -eq "ok") {
            Write-Ok "$Name installed and importable"
        } else {
            Write-Warn "$Name installed but import failed - check dependencies"
        }
    } catch {
        Write-Warn "$Name installed but import failed - check dependencies"
    }

    return @{ Name = $Name; Dir = $dir; Python = $venvPython; Module = $Module }
}

# Always install wintools-mcp
$wintoolsInfo = Install-MCP -Name "wintools-mcp" -Repo "wintools-mcp" -Extras "fk,dev"

# Optional components
if ($installAiir) {
    $aiirInfo = Install-MCP -Name "aiir" -Repo "aiir" -Extras "dev"
}
if ($installForensic) {
    Install-MCP -Name "forensic-mcp" -Repo "forensic-mcp" -Extras "dev"
}

# Add aiir to PATH if installed
if ($installAiir) {
    $aiirBin = Join-Path $InstallDir "aiir\.venv\Scripts"
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($currentPath -notlike "*$aiirBin*") {
        Write-Info "Adding aiir to user PATH..."
        [Environment]::SetEnvironmentVariable("Path", "$aiirBin;$currentPath", "User")
        $env:Path = "$aiirBin;$env:Path"
        Write-Ok "Added to PATH (restart terminal to take effect)"
    }
}

# --- Phase 4: Tool Scan ---
Write-Header "Phase 4: Scanning for Forensic Tools"

Write-Host "Checking which forensic tools are installed on this system..."
Write-Host ""

$wintoolsPython = $wintoolsInfo.Python
$scanResult = & $wintoolsPython -m wintools_mcp --scan 2>$null

if ($scanResult) {
    Write-Host $($scanResult -join "`n")
} else {
    Write-Warn "Tool scan could not run. You can try manually:"
    Write-Host "  $wintoolsPython -m wintools_mcp --scan"
}

Write-Host ""

# Offer to generate install helper for missing tools
$missingJson = & $wintoolsPython -c @"
import json
from wintools_mcp.inventory import scan_tools
result = scan_tools()
missing = result['missing_tools']
print(json.dumps(missing))
"@ 2>$null

if ($missingJson) {
    try {
        $missing = $missingJson | ConvertFrom-Json
        if ($missing.Count -gt 0) {
            Write-Host ""
            if (Read-YesNo "Generate install-missing-tools.ps1 helper script?" $true) {
                $helperPath = Join-Path $InstallDir "install-missing-tools.ps1"
                $helperLines = @(
                    "# Auto-generated helper to install missing forensic tools"
                    "# Review each command before running — some require manual download."
                    ""
                )

                foreach ($tool in $missing) {
                    $helperLines += "# --- $($tool.name) ---"
                    $helperLines += "# $($tool.description)"
                    if ($tool.install_methods) {
                        foreach ($im in $tool.install_methods) {
                            if ($im.command) {
                                $helperLines += "# $($im.method):"
                                $helperLines += "$($im.command)"
                            }
                            if ($im.url) {
                                $helperLines += "# Download: $($im.url)"
                            }
                        }
                    }
                    $helperLines += ""
                }

                $helperLines -join "`n" | Set-Content -Path $helperPath -Encoding UTF8
                Write-Ok "Generated: $helperPath"
                Write-Host "  Review and run to install missing tools."
            }
        }
    } catch { }
}

# --- Phase 5: Configure ---
Write-Header "Phase 5: Configuration"

# Examiner identity
Write-Host "Your examiner name identifies your work in case files and audit trails."
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
Write-Ok "Set AIIR_EXAMINER=$Examiner (user environment variable)"

# --- Phase 6: LLM Client Configuration ---
Write-Header "Phase 6: Configure LLM Client"

Write-Host "How will you use wintools-mcp?"
Write-Host ""
Write-Host "  Mode A: Standalone" -ForegroundColor White
Write-Host "    LLM client runs on THIS Windows machine."
Write-Host "    wintools-mcp runs as a local stdio MCP server."
Write-Host ""
Write-Host "  Mode B: Remote (serve to SIFT gateway)" -ForegroundColor White
Write-Host "    LLM client runs on a SIFT workstation."
Write-Host "    wintools-mcp serves over HTTP for the gateway to call."
Write-Host ""
Write-Host "  1. Standalone - Claude Code"
Write-Host "  2. Standalone - Claude Desktop"
Write-Host "  3. Standalone - Cursor"
Write-Host "  4. Standalone - print config (other client)"
Write-Host "  5. Remote - serve to SIFT gateway"
Write-Host "  6. Skip (configure later)"
Write-Host ""

$modeChoice = Read-Prompt "Choose" "1"

function Build-McpJson {
    param([string]$PythonPath, [string]$Module)

    $serverEntry = @{
        command = $PythonPath
        args = @("-m", $Module)
        env = @{ AIIR_EXAMINER = $Examiner }
    }
    $config = @{ mcpServers = @{ "wintools-mcp" = $serverEntry } }
    return $config | ConvertTo-Json -Depth 4
}

$mcpJson = Build-McpJson -PythonPath $wintoolsPython -Module "wintools_mcp"

switch ($modeChoice) {
    "1" {
        # Claude Code - .mcp.json
        $projectDir = Read-Prompt "Project directory for .mcp.json" (Get-Location)
        $outputPath = Join-Path $projectDir ".mcp.json"
        $mcpJson | Set-Content -Path $outputPath -Encoding UTF8
        Write-Ok "Generated: $outputPath"
    }
    "2" {
        # Claude Desktop
        $outputPath = Join-Path $env:APPDATA "Claude\claude_desktop_config.json"
        $outputDir = Split-Path $outputPath
        if (-not (Test-Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }
        # Merge with existing if present
        if (Test-Path $outputPath) {
            try {
                $existing = Get-Content $outputPath -Raw | ConvertFrom-Json
                $new = $mcpJson | ConvertFrom-Json
                foreach ($key in $new.mcpServers.PSObject.Properties.Name) {
                    if (-not $existing.mcpServers) {
                        $existing | Add-Member -Type NoteProperty -Name mcpServers -Value @{}
                    }
                    $existing.mcpServers | Add-Member -Type NoteProperty -Name $key -Value $new.mcpServers.$key -Force
                }
                $existing | ConvertTo-Json -Depth 4 | Set-Content -Path $outputPath -Encoding UTF8
                Write-Ok "Merged into existing: $outputPath"
            } catch {
                $mcpJson | Set-Content -Path $outputPath -Encoding UTF8
                Write-Ok "Generated: $outputPath"
            }
        } else {
            $mcpJson | Set-Content -Path $outputPath -Encoding UTF8
            Write-Ok "Generated: $outputPath"
        }
    }
    "3" {
        # Cursor
        $projectDir = Read-Prompt "Project directory for .cursor/mcp.json" (Get-Location)
        $outputDir = Join-Path $projectDir ".cursor"
        if (-not (Test-Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }
        $outputPath = Join-Path $outputDir "mcp.json"
        $mcpJson | Set-Content -Path $outputPath -Encoding UTF8
        Write-Ok "Generated: $outputPath"
    }
    "4" {
        # Print config
        Write-Host ""
        Write-Host "Add this to your MCP client configuration:" -ForegroundColor White
        Write-Host ""
        Write-Host $mcpJson
        Write-Host ""
    }
    "5" {
        # Remote mode
        $httpHost = Read-Prompt "HTTP bind address" "0.0.0.0"
        $httpPort = Read-Prompt "HTTP port" "4624"
        $apiKey = -join ((48..57) + (97..122) | Get-Random -Count 32 | ForEach-Object { [char]$_ })

        Write-Host ""
        Write-Host "Remote mode configuration:" -ForegroundColor White
        Write-Host ""
        Write-Host "  Start wintools-mcp:"
        Write-Host "    $wintoolsPython -m wintools_mcp --http --host $httpHost --port $httpPort"
        Write-Host ""
        Write-Host "  Tell your SIFT administrator:" -ForegroundColor White
        $localIp = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "Loopback*" -and $_.PrefixOrigin -ne "WellKnown" } | Select-Object -First 1).IPAddress
        if (-not $localIp) { $localIp = "THIS_MACHINE_IP" }
        Write-Host "    URL:      http://${localIp}:${httpPort}"
        Write-Host "    Examiner: $Examiner"
        Write-Host ""
        Write-Host "  SIFT gateway.yaml entry:" -ForegroundColor White
        Write-Host "    wintools-mcp:"
        Write-Host "      type: http"
        Write-Host "      url: `"http://${localIp}:${httpPort}/mcp`""
        Write-Host "      enabled: true"
        Write-Host ""

        # Save a startup script
        $startupPath = Join-Path $InstallDir "start-wintools.ps1"
        @"
# Start wintools-mcp in HTTP mode for remote access
`$env:AIIR_EXAMINER = "$Examiner"
& "$wintoolsPython" -m wintools_mcp --http --host $httpHost --port $httpPort
"@ | Set-Content -Path $startupPath -Encoding UTF8
        Write-Ok "Generated startup script: $startupPath"

        # Firewall rule
        Write-Host ""
        if (Read-YesNo "Add Windows Firewall rule for port $httpPort?" $true) {
            try {
                $ruleName = "AIIR wintools-mcp"
                $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
                if ($existing) {
                    Write-Info "Firewall rule already exists"
                } else {
                    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort ([int]$httpPort) -Action Allow | Out-Null
                    Write-Ok "Firewall rule added for TCP port $httpPort"
                }
            } catch {
                Write-Warn "Could not add firewall rule (run as Administrator)"
                Write-Host "  Manual: netsh advfirewall firewall add rule name=`"AIIR wintools-mcp`" dir=in action=allow protocol=TCP localport=$httpPort"
            }
        }
    }
    "6" {
        Write-Info "Skipping client configuration."
    }
}

# --- Phase 7: Team Deployment (optional) ---
Write-Host ""
if (Read-YesNo "Connect to a SIFT case share?" $false) {
    Write-Header "Phase 7: Team Deployment"

    $sharePath = Read-Prompt "SIFT share path (e.g., \\sift-workstation\cases)" ""

    if ($sharePath) {
        $driveLetter = Read-Prompt "Map to drive letter" "Z"
        $driveLetter = $driveLetter.TrimEnd(":")

        Write-Host ""
        Write-Host "Mapping $sharePath to ${driveLetter}:..."
        try {
            net use "${driveLetter}:" $sharePath /persistent:yes 2>$null
            Write-Ok "Mapped $sharePath to ${driveLetter}:"
        } catch {
            Write-Warn "Could not map drive. Try manually:"
            Write-Host "  net use ${driveLetter}: $sharePath /persistent:yes"
        }

        Write-Host ""
        Write-Host "To use a case on the share:" -ForegroundColor White
        Write-Host "  `$env:AIIR_CASE_DIR = `"${driveLetter}:\INC-2026-0001`""
        Write-Host ""
        Write-Host "Each examiner writes to: examiners\$Examiner\ within the case."
    }

    # Connectivity test
    Write-Host ""
    if (Read-YesNo "Test connectivity to SIFT gateway?" $false) {
        $siftHost = Read-Prompt "SIFT gateway host" ""
        if ($siftHost) {
            $siftPort = Read-Prompt "Gateway port" "4508"
            try {
                $response = Invoke-WebRequest -Uri "http://${siftHost}:${siftPort}/health" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
                Write-Ok "Connected to SIFT gateway at ${siftHost}:${siftPort}"
            } catch {
                Write-Warn "Cannot reach ${siftHost}:${siftPort} - ensure aiir-gateway is running"
            }
        }
    }
}

# --- Summary ---
Write-Header "Installation Complete"

Write-Host "Installed components:"
Write-Ok "wintools-mcp"
if ($installAiir) { Write-Ok "aiir CLI" }
if ($installForensic) { Write-Ok "forensic-mcp" }
Write-Host ""
Write-Host "Examiner:    $Examiner"
Write-Host "Install dir: $InstallDir"
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "  1. Install any missing forensic tools reported above"
Write-Host "  2. Restart your terminal for PATH changes to take effect"
if ($modeChoice -eq "5") {
    Write-Host "  3. Start wintools-mcp: $InstallDir\start-wintools.ps1"
    Write-Host "  4. Configure SIFT gateway to connect to this machine"
} else {
    Write-Host "  3. Start your LLM client and begin an investigation"
    Write-Host "  4. Run: $wintoolsPython -m wintools_mcp --scan  (to re-check tools)"
}
if ($installAiir) {
    Write-Host "  5. Run: aiir setup test  (to verify connectivity)"
}
Write-Host ""
