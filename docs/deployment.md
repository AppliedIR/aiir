# Deployment Guide

## Installation Tiers

The `sift-install.sh` installer offers three tiers:

| Tier | Packages | Use Case |
|------|----------|----------|
| **Quick** | forensic-mcp, case-mcp, report-mcp, sift-mcp, sift-gateway, sift-common, forensic-knowledge | Core investigation. Minimal install. |
| **Recommended** | Quick + forensic-rag, windows-triage | Adds RAG search and baseline validation. |
| **Custom** | Select individual packages | Fine-grained control. |

OpenCTI-mcp is always optional (requires an OpenCTI instance).

## SIFT Workstation Setup

### Prerequisites

- Ubuntu 22.04+ (SIFT Workstation recommended)
- Python 3.11+
- Git

### Install

```bash
git clone https://github.com/AppliedIR/sift-mcp.git && cd sift-mcp
./sift-install.sh
```

The installer:
1. Creates a Python virtual environment
2. Installs selected packages via pip
3. Generates `gateway.yaml` configuration
4. Creates a systemd service for the gateway (optional)
5. Starts the gateway

### Install the CLI

```bash
git clone https://github.com/AppliedIR/aiir.git && cd aiir
./aiir-install.sh
```

The CLI installer:
1. Installs the `aiir` package
2. Runs `aiir setup client` to configure your LLM client
3. For Claude Code, deploys forensic controls (sandbox, audit hook, discipline docs)

## Windows Workstation Setup

### Prerequisites

- Windows 10/11 or Windows Server 2019+
- Python 3.11+
- Forensic tools (Zimmerman suite, Hayabusa) installed

### Install

```powershell
git clone https://github.com/AppliedIR/wintools-mcp.git
cd wintools-mcp
.\scripts\setup-windows.ps1
```

The installer:
1. Requires typing `security_hole` to acknowledge the security implications
2. Creates a Python virtual environment
3. Installs the wintools-mcp package
4. Generates a bearer token (`aiir_wt_` prefix)
5. Creates `config.yaml` with the token
6. Optionally creates a Windows service

### Connecting to SIFT

Copy the bearer token from the installer output. On the SIFT workstation, add a wintools backend to `gateway.yaml`:

```yaml
backends:
  wintools-mcp:
    type: http
    url: "http://WIN_IP:4624/mcp"
    bearer_token: "aiir_wt_..."
```

Or use `aiir setup client` with the `--windows` flag:

```bash
aiir setup client --sift=http://127.0.0.1:4508 --windows=WIN_IP:4624
```

### SMB Configuration

wintools-mcp accesses the case directory on SIFT via SMB for audit trail writes. Set `AIIR_SHARE_ROOT` to the SMB mount point:

```powershell
$env:AIIR_SHARE_ROOT = "E:\cases\SRL2\"
```

## Remote Access (TLS + Auth)

For deployments where the LLM client runs on a different machine:

### Enable Remote Access

```bash
./sift-install.sh --remote
```

This generates:
- Local CA certificate and gateway TLS certificate at `~/.aiir/tls/`
- Bearer token (`aiir_gw_` prefix) in `gateway.yaml`
- Gateway binds to `0.0.0.0:4508` with TLS

### Client Setup

On the remote machine:

1. Import the CA certificate (`~/.aiir/tls/ca-cert.pem`) into the OS trust store
2. Copy the bearer token from the installer output
3. Configure the client:

```bash
aiir setup client --remote --sift=https://SIFT_IP:4508 --token=aiir_gw_...
```

### Join Codes

For easier remote setup, generate a join code on the SIFT workstation:

```bash
aiir setup join-code --expires 2    # 2-hour expiry
```

On the remote machine:

```bash
aiir join --sift SIFT_IP --code ABC123
```

## Multi-Examiner Deployment

Each examiner runs their own full stack on their own SIFT workstation with a local case directory.

### Setup

Each examiner installs independently:

```bash
git clone https://github.com/AppliedIR/sift-mcp.git && cd sift-mcp
./sift-install.sh
cd .. && git clone https://github.com/AppliedIR/aiir.git && cd aiir
./aiir-install.sh
```

### Collaboration

Examiners share findings via JSON export/import:

```bash
# Alice exports her findings
aiir export --file findings-alice.json

# Bob imports Alice's findings
aiir merge --file findings-alice.json
```

IDs include the examiner name (`F-alice-001`, `F-bob-003`) so they never collide. Merge uses last-write-wins by `modified_at` timestamp. APPROVED findings are protected from overwrite.

## Gateway Configuration

The gateway is configured via `gateway.yaml` (typically at `~/.aiir/gateway.yaml`).

### Backend Configuration

```yaml
backends:
  forensic-mcp:
    type: stdio
    command: ["python", "-m", "forensic_mcp"]
  case-mcp:
    type: stdio
    command: ["python", "-m", "case_mcp"]
  report-mcp:
    type: stdio
    command: ["python", "-m", "report_mcp"]
  sift-mcp:
    type: stdio
    command: ["python", "-m", "sift_mcp"]
  forensic-rag-mcp:
    type: stdio
    command: ["python", "-m", "rag_mcp"]
  windows-triage-mcp:
    type: stdio
    command: ["python", "-m", "windows_triage"]
  opencti-mcp:
    type: stdio
    command: ["python", "-m", "opencti_mcp"]
  wintools-mcp:
    type: http
    url: "http://WIN_IP:4624/mcp"
    bearer_token: "aiir_wt_..."
```

### Authentication

```yaml
api_keys:
  aiir_gw_a1b2c3d4e5f6a1b2c3d4e5f6:
    examiner: "alice"
    role: "examiner"
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SIFT_TIMEOUT` | `600` | Default command timeout (seconds) |
| `SIFT_TOOL_PATHS` | (none) | Extra binary search paths (colon-separated) |
| `SIFT_HAYABUSA_DIR` | `/opt/hayabusa` | Hayabusa install location |
| `AIIR_CASE_DIR` | (none) | Active case directory (falls back to `~/.aiir/active_case`) |
| `AIIR_CASES_DIR` | (none) | Root directory containing all cases |
| `AIIR_EXAMINER` | (none) | Examiner identity |

### wintools-mcp Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WINTOOLS_TIMEOUT` | `600` | Default command timeout (seconds) |
| `WINTOOLS_HOST` | `127.0.0.1` | HTTP bind address |
| `WINTOOLS_PORT` | `4624` | HTTP port |
| `WINTOOLS_TOOL_PATHS` | (none) | Additional binary search directories |
| `AIIR_SHARE_ROOT` | (none) | SMB mount root for evidence and extractions |
| `AIIR_EXAMINER` | OS user | Examiner identity |

## Client Configuration

### Claude Code

`aiir setup client --client=claude-code` deploys:

- `.mcp.json` with Streamable HTTP endpoint
- `.claude/settings.json` with kernel-level sandbox and PostToolUse audit hook
- `FORENSIC_DISCIPLINE.md` and `TOOL_REFERENCE.md` for LLM context
- `CLAUDE.md` referencing AGENTS.md

### Claude Desktop

`aiir setup client --client=claude-desktop` generates `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "aiir": {
      "type": "streamable-http",
      "url": "http://127.0.0.1:4508/mcp"
    }
  }
}
```

### Cursor

`aiir setup client --client=cursor` generates `.cursor/mcp.json`.

### External MCPs

Two external MCPs are configured during client setup:

- **Zeltser IR Writing MCP** (`https://website-mcp.zeltser.com/mcp`) — Required for report generation
- **MS Learn MCP** (`https://learn.microsoft.com/api/mcp`) — Optional, Microsoft documentation search

## Systemd Service

The installer can create a systemd service for the gateway:

```bash
sudo systemctl enable aiir-gateway
sudo systemctl start aiir-gateway
sudo systemctl status aiir-gateway
```

Logs:
```bash
journalctl -u aiir-gateway -f
```

## Testing Connectivity

```bash
aiir setup test    # Test all configured MCP endpoints
```

This verifies connectivity to the gateway and all backend MCPs.
