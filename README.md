# AIIR CLI

Command-line interface for **human-in-the-loop forensic investigation management**. The `aiir` CLI provides the actions that only a human analyst should perform: approving findings, rejecting conclusions, managing evidence integrity, executing forensic commands with audit trails, and configuring the investigation platform.

## Installation Options

### Option A: As Part of AIIR (Recommended)

This CLI is designed as a component of the AIIR (Applied Incident Response) platform, working alongside [forensic-mcp](https://github.com/AppliedIR/forensic-mcp).

```bash
git clone https://github.com/AppliedIR/aiir.git
cd aiir
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

### Option B: Standalone Installation

Use standalone when you need the approval workflow without the full AIIR platform.

See the **Quick Start** section below.

---

## Overview

The AI assistant (via forensic-mcp) stages findings and timeline events as DRAFT. The `aiir` CLI is how a human analyst reviews, approves, or rejects those items. This separation is structural — the AI cannot approve its own work.

> **Important:** The `aiir` CLI is a human-only tool. It is not designed to be called by the AI orchestrator. Every approval and rejection is logged with analyst identity, timestamp, and OS user for full accountability.

**Key Capabilities:**

- **Interactive Review** - Walk through each staged item with approve/edit/note/reject/todo/skip options
- **Finding Modification** - Edit AI-generated findings via `$EDITOR`, add examiner notes, override interpretations
- **Team Review** - Filter by creator analyst, review only findings or timeline events
- **Investigation TODOs** - Create and manage action items with assignee, priority, and finding links
- **Evidence Management** - Register evidence files (SHA256 + read-only), lock/unlock evidence directories
- **Forensic Execution** - Run commands with interactive confirmation, audit trail, and case context
- **Platform Setup** - Interactive `aiir setup` to detect MCPs and generate config for Claude Code, Claude Desktop, and OpenWebUI
- **Analyst Identity** - Configurable identity resolution for audit accountability

## Commands

### approve

Interactive review with per-item options:

```bash
# Interactive review — walk through each DRAFT item
aiir approve
#   [a]pprove  [e]dit & approve  [n]ote & approve
#   [r]eject   [t]odo            [s]kip  [q]uit

# Approve specific IDs
aiir approve F-001 F-002 T-001

# Approve with examiner note
aiir approve F-001 --note "Finding correct. Malware family unconfirmed."

# Approve with field override
aiir approve F-001 --interpretation "Process masquerading confirmed, no lateral movement"

# Approve with $EDITOR (opens finding as YAML for modification)
aiir approve F-001 --edit

# Team review: filter by creator analyst
aiir approve --by jane

# Review only findings (skip timeline events)
aiir approve --findings-only

# Review only timeline events
aiir approve --timeline-only
```

When approving with modifications, original AI content is preserved in `examiner_modifications` for audit trail.

### reject

```bash
# Reject with reason
aiir reject F-003 --reason "Insufficient evidence for attribution"
```

### review

```bash
# Case summary (default)
aiir review

# Findings grouped by status
aiir review --findings

# Full detail (with --findings or --timeline)
aiir review --findings --detail

# Cross-check findings against approval records
aiir review --verify

# Extract IOCs from findings grouped by status
aiir review --iocs

# Timeline events
aiir review --timeline

# Evidence registry and access log
aiir review --evidence

# Audit trail (last N entries)
aiir review --audit --limit 100

# Investigation TODOs
aiir review --todos
aiir review --todos --open
```

### todo

```bash
# List open TODOs
aiir todo

# List all TODOs including completed
aiir todo --all

# Filter by assignee
aiir todo --assignee jane

# Add a new TODO
aiir todo add "Run volatility on server-04 memory dump" --assignee jane --priority high --finding F-003

# Mark TODO as completed
aiir todo complete TODO-001

# Update a TODO
aiir todo update TODO-002 --note "Waiting on third party" --priority low
```

### exec

```bash
# Execute forensic command with audit trail
aiir exec --purpose "Extract MFT from image" -- fls -r -m / image.E01
```

### evidence

```bash
# Register evidence file (SHA256 hash + chmod 444)
aiir register-evidence /path/to/image.E01 --description "Disk image from workstation"

# Lock evidence directory (all files read-only, dir set to 555)
aiir lock-evidence

# Unlock evidence directory for new files (interactive confirmation)
aiir unlock-evidence
```

### setup

Interactive setup wizard to detect installed MCP servers and generate configuration files:

```bash
# Interactive setup
aiir setup

# Non-interactive (generates Claude Code config only)
aiir setup --non-interactive

# Force re-prompting for all values
aiir setup --force-reprompt
```

Setup phases:
1. **Detect** - Finds installed MCP servers (system Python and venvs)
2. **Credentials** - Configures OpenCTI URL/token, REMnux host (if applicable)
3. **Client Selection** - Choose Claude Code, Claude Desktop, and/or OpenWebUI
4. **Generate** - Writes `.mcp.json`, `claude_desktop_config.json`, and/or `gateway.yaml`

### config

```bash
# Set analyst identity
aiir config --analyst "jane.doe"

# Show current configuration
aiir config --show

# Set approval PIN
aiir config --setup-pin

# Reset approval PIN
aiir config --reset-pin
```

## Analyst Identity

Every approval, rejection, and execution is logged with analyst identity. Resolution order:

| Priority | Source | Example |
|----------|--------|---------|
| 1 | `--analyst` flag | `aiir approve --analyst jane.doe F-001` |
| 2 | `AIIR_ANALYST` env var | `export AIIR_ANALYST=jane.doe` |
| 3 | `~/.aiir/config.yaml` | `analyst: jane.doe` |
| 4 | OS username (fallback) | Warns if unconfigured |

The OS username is always captured alongside the explicit analyst identity for accountability.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `AIIR_ANALYST` | (none) | Analyst identity for audit trail |
| `AIIR_CASE_DIR` | (none) | Active case directory |
| `AIIR_CASES_DIR` | `cases` | Root directory for case storage |

## Quick Start

```bash
git clone https://github.com/AppliedIR/aiir.git
cd aiir
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Set your identity
aiir config --analyst "your.name"

# Review a case
aiir review --case INC-2026-0219120000
```

## Project Structure

```
aiir/
├── src/aiir_cli/
│   ├── __init__.py
│   ├── main.py                     # Entry point and argument parser
│   ├── identity.py                 # Analyst identity resolution
│   ├── case_io.py                  # Shared case file I/O
│   ├── commands/
│   │   ├── approve.py              # Interactive review with edit/note/todo options
│   │   ├── reject.py               # Reject with required reason
│   │   ├── review.py               # Case status, findings, timeline, audit, TODOs display
│   │   ├── execute.py              # Forensic command execution with audit
│   │   ├── evidence.py             # Lock/unlock/register evidence
│   │   ├── config.py               # Analyst identity and PIN configuration
│   │   ├── todo.py                 # TODO management commands
│   │   └── setup.py                # Interactive platform setup
│   └── setup/
│       ├── detect.py               # MCP server detection (system + venvs)
│       ├── wizard.py               # Interactive credential and client wizards
│       └── config_gen.py           # Config file generation (.mcp.json, desktop, gateway)
├── tests/
│   ├── test_identity.py            # Identity resolution tests
│   ├── test_approval_auth.py       # PIN and /dev/tty confirmation tests
│   ├── test_approve_reject.py      # Approval workflow tests (interactive + specific-ID)
│   ├── test_case_io.py             # Shared I/O module tests
│   ├── test_review.py              # Review display tests
│   ├── test_execute.py             # Forensic execution tests
│   ├── test_evidence_cmds.py       # Evidence management tests
│   ├── test_config.py              # Config command tests
│   ├── test_todo.py                # TODO command tests
│   └── test_setup.py               # Setup wizard and config generation tests
├── pyproject.toml
└── README.md
```

## Development

```bash
# Run tests
.venv/bin/pytest tests/ -v

# Run with coverage
.venv/bin/pytest tests/ --cov=aiir_cli --cov-report=term-missing
```

## Responsible Use

This tool exists because AI-assisted forensic analysis requires human oversight. The `aiir` CLI enforces that boundary.

**Core principles:**

- **Human authority is final.** The AI stages findings as DRAFT. Only a human analyst can approve or reject them. This is a structural guarantee, not a suggestion.
- **The analyst owns the work product.** Approving a finding means you have reviewed it, verified the evidence, and are prepared to stand behind the conclusion. AI assistance does not reduce your responsibility.
- **Rejections require reasoning.** When you reject a finding, you must provide a reason. This creates a record that improves future analysis and prevents silent dismissal of inconvenient evidence.
- **Every action is auditable.** Approvals, rejections, evidence access, and command execution are logged with analyst identity and timestamp. The audit trail is the foundation of defensible forensic work.
- **AI is an assistive tool, not a replacement.** A trained analyst reviewing AI-proposed findings should apply the same critical thinking they would to any other tool output. Corroborate, verify, and document.

## Acknowledgments

Architecture and direction by Steve Anson. Implementation by Claude Code (Anthropic).

## License

MIT License. See [LICENSE](LICENSE) for details.
