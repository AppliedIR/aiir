# AIR CLI

Command-line interface for **human-in-the-loop forensic investigation management**. The `air` CLI provides the actions that only a human analyst should perform: approving findings, rejecting conclusions, managing evidence integrity, and executing forensic commands with audit trails.

## Installation Options

### Option A: As Part of AIR (Recommended)

This CLI is designed as a component of the AIR (Applied Incident Response) platform, working alongside [forensic-mcp](https://github.com/AppliedIR/forensic-mcp).

```bash
git clone https://github.com/AppliedIR/cli.git
cd cli
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

### Option B: Standalone Installation

Use standalone when you need the approval workflow without the full AIR platform.

See the **Quick Start** section below.

**For detailed setup guidance:** See `SETUP.md`

---

## Overview

The AI assistant (via forensic-mcp) stages findings and timeline events as DRAFT. The `air` CLI is how a human analyst reviews, approves, or rejects those items. This separation is structural — the AI cannot approve its own work.

> **Important:** The `air` CLI is a human-only tool. It is not designed to be called by the AI orchestrator. Every approval and rejection is logged with analyst identity, timestamp, and OS user for full accountability.

**Key Capabilities:**

- **Approve/Reject Findings** - Review AI-staged findings one by one or in batch, with mandatory reasons for rejections
- **Interactive Review** - Walk through each staged item with full context before deciding
- **Evidence Management** - Register evidence files (SHA256 + read-only), lock/unlock evidence directories
- **Forensic Execution** - Run commands with interactive confirmation, audit trail, and case context
- **Case Review** - View case summary, findings by status, evidence registry, and full audit trail
- **Analyst Identity** - Configurable identity resolution for audit accountability

## Commands

### approve

```bash
# Approve specific findings/timeline events by ID
air approve F-001 F-002 T-001

# Review all staged items, then batch approve
air approve --all

# Interactive one-by-one review
air approve --review
```

### reject

```bash
# Reject with required reason
air reject F-003 --reason "Insufficient evidence for attribution"
```

### review

```bash
# Case summary (default)
air review

# Findings grouped by status
air review --findings

# Evidence registry and access log
air review --evidence

# Audit trail (last N entries)
air review --audit --limit 100
```

### exec

```bash
# Execute forensic command with audit trail
air exec --purpose "Extract MFT from image" -- fls -r -m / image.E01
```

### evidence

```bash
# Register evidence file (SHA256 hash + chmod 444)
air register-evidence /path/to/image.E01 --description "Disk image from workstation"

# Lock evidence directory (all files read-only, dir set to 555)
air lock-evidence

# Unlock evidence directory for new files (interactive confirmation)
air unlock-evidence
```

### config

```bash
# Set analyst identity
air config --analyst "jane.doe"

# Show current configuration
air config --show
```

## Analyst Identity

Every approval, rejection, and execution is logged with analyst identity. Resolution order:

| Priority | Source | Example |
|----------|--------|---------|
| 1 | `--analyst` flag | `air approve --analyst jane.doe F-001` |
| 2 | `AIR_ANALYST` env var | `export AIR_ANALYST=jane.doe` |
| 3 | `~/.air/config.yaml` | `analyst: jane.doe` |
| 4 | OS username (fallback) | Warns if unconfigured |

The OS username is always captured alongside the explicit analyst identity for accountability.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `AIR_ANALYST` | (none) | Analyst identity for audit trail |
| `AIR_CASE_DIR` | (none) | Active case directory |
| `AIR_CASES_DIR` | `cases` | Root directory for case storage |

## Quick Start

```bash
git clone https://github.com/AppliedIR/cli.git
cd cli
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Set your identity
air config --analyst "your.name"

# Review a case
air review --case INC-2026-0219120000
```

## Project Structure

```
cli/
├── src/air_cli/
│   ├── __init__.py
│   ├── main.py                  # Entry point and argument parser
│   ├── identity.py              # Analyst identity resolution
│   ├── case_io.py               # Shared case file I/O (same formats as forensic-mcp)
│   └── commands/
│       ├── __init__.py
│       ├── approve.py           # Approve staged findings/events
│       ├── reject.py            # Reject with required reason
│       ├── review.py            # Case status, audit, evidence, findings display
│       ├── execute.py           # Forensic command execution with audit
│       ├── evidence.py          # Lock/unlock/register evidence
│       └── config.py            # Analyst identity configuration
├── tests/
│   ├── test_identity.py         # Identity resolution tests
│   ├── test_approve_reject.py   # Approval and rejection workflow tests
│   └── test_case_io.py          # Shared I/O module tests
├── pyproject.toml
└── README.md
```

## Development

```bash
# Run tests
.venv/bin/pytest tests/ -v

# Run with coverage
.venv/bin/pytest tests/ --cov=air_cli --cov-report=term-missing
```

## Responsible Use

This tool exists because AI-assisted forensic analysis requires human oversight. The `air` CLI enforces that boundary.

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
