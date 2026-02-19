# AIR CLI — Setup Guide

## Prerequisites

- Python 3.10+
- A case directory created by forensic-mcp (or manually)

## Installation

### 1. Clone and install

```bash
git clone https://github.com/AppliedIR/cli.git
cd cli
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 2. Set analyst identity

```bash
air config --analyst "your.name"
```

Or via environment variable:

```bash
export AIR_ANALYST="your.name"
```

### 3. Verify

```bash
air --version
air config --show
```

### 4. Run tests

```bash
pytest tests/ -v
```

## Configuration

### Analyst Identity

Identity is resolved in this order:

1. `--analyst` flag on the command
2. `AIR_ANALYST` environment variable
3. `~/.air/config.yaml` file
4. OS username (fallback, triggers a warning)

```bash
# Set via config file (persistent)
air config --analyst "jane.doe"

# Set via environment (session)
export AIR_ANALYST="jane.doe"

# Override per-command
air approve --analyst "jane.doe" F-001
```

### Case Resolution

The CLI needs to know which case to operate on:

| Method | Example |
|--------|---------|
| `--case` flag | `air review --case INC-2026-02191200` |
| `AIR_CASE_DIR` env var | `export AIR_CASE_DIR=/path/to/cases/INC-2026-02191200` |
| `.air/active_case` file | Contains case ID, resolved against `AIR_CASES_DIR` |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AIR_ANALYST` | (none) | Analyst identity |
| `AIR_CASE_DIR` | (none) | Active case directory path |
| `AIR_CASES_DIR` | `cases` | Root directory containing all cases |

## Typical Workflow

```bash
# 1. AI creates a case and stages findings via forensic-mcp
#    (this happens in the Claude Code session)

# 2. Review what was staged
air review --findings

# 3. Approve good findings
air approve F-001 F-002

# 4. Reject findings that need work
air reject F-003 --reason "Attribution requires 3+ evidence sources"

# 5. Register evidence files
air register-evidence /path/to/memory.raw --description "Memory dump from DC01"

# 6. Lock evidence directory
air lock-evidence

# 7. Run forensic commands with audit trail
air exec --purpose "Parse prefetch files" -- python prefetch_parser.py /evidence/prefetch/

# 8. Review audit trail
air review --audit
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `No active case` | Use `--case <id>` or set `AIR_CASE_DIR` |
| `command not found: air` | Ensure venv is activated and `pip install -e .` was run |
| Identity warning on every command | Run `air config --analyst "your.name"` |
| Permission denied on evidence | Use `air unlock-evidence` (requires confirmation) |
