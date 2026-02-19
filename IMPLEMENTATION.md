# AIR CLI — Implementation Details

## Architecture

```
┌───────────────────────────────────────────────────┐
│                    Human Analyst                    │
│                         │                          │
│                    air CLI (argparse)               │
│                         │                          │
│    ┌────────────────────┼────────────────────┐     │
│    │                    │                    │     │
│    ▼                    ▼                    ▼     │
│  approve.py        review.py          evidence.py  │
│  reject.py         execute.py         config.py    │
│    │                    │                    │     │
│    └────────────────────┼────────────────────┘     │
│                         │                          │
│                    identity.py                      │
│                    case_io.py                       │
│                         │                          │
│              case directory (filesystem)             │
│              (shared with forensic-mcp)             │
└───────────────────────────────────────────────────┘
```

## Module Responsibilities

| Module | Purpose |
|--------|---------|
| `main.py` | Entry point; argparse setup with subcommands; identity check; command dispatch |
| `identity.py` | Analyst identity resolution (flag > env > config > os_user); unconfigured warning |
| `case_io.py` | Shared I/O: case dir resolution, findings/timeline load/save, approval log writer |
| `commands/approve.py` | Approve by ID, `--all` batch, `--review` interactive; writes approvals.jsonl |
| `commands/reject.py` | Reject by ID with required reason; writes approvals.jsonl |
| `commands/review.py` | Case summary, findings by status, evidence registry, audit trail display |
| `commands/execute.py` | Command execution with confirmation, audit trail (exec.jsonl + ACTIONS.md) |
| `commands/evidence.py` | Lock (chmod 444/555), unlock (chmod 755), register (SHA256 + chmod 444 + registry) |
| `commands/config.py` | Read/write `~/.air/config.yaml`; set analyst identity |

## Data Flow

### Approval Flow

```
1. Human runs: air approve F-001
2. case_io.py resolves case directory (--case flag, AIR_CASE_DIR env, .air/active_case)
3. approve.py loads .audit/findings.json
4. Finds F-001 with status DRAFT
5. Sets status to APPROVED, adds approved_at timestamp and approved_by identity
6. Saves findings.json
7. Writes approval record to .audit/approvals.jsonl
```

### Rejection Flow

```
1. Human runs: air reject F-001 --reason "Insufficient evidence"
2. Same resolution as approve
3. Sets status to REJECTED, adds rejected_at, rejected_by, rejection_reason
4. Saves findings.json
5. Writes rejection record (with reason) to .audit/approvals.jsonl
```

### Interactive Review Flow

```
1. Human runs: air approve --review
2. Loads all DRAFT findings and timeline events
3. For each item, displays full context (title, confidence, evidence, observation, interpretation)
4. Prompts: Approve? [Y/n/q]
5. Y = approve, n = skip, q = quit
6. Saves all changes at the end
```

## Identity Resolution

```
get_analyst_identity(flag_override=None)
│
├── flag_override provided? → return {analyst: flag, source: "flag"}
├── AIR_ANALYST env var set? → return {analyst: env, source: "env"}
├── ~/.air/config.yaml has analyst? → return {analyst: config, source: "config"}
└── fallback → return {analyst: os_user, source: "os_user"} + stderr warning
```

Every identity dict always includes `os_user` regardless of source, for audit accountability.

## Shared File Formats

The CLI reads and writes the same files as forensic-mcp. This is the integration contract:

| File | Format | Writer | Reader |
|------|--------|--------|--------|
| `.audit/findings.json` | JSON array of finding objects | forensic-mcp, air CLI | Both |
| `.audit/timeline.json` | JSON array of event objects | forensic-mcp, air CLI | Both |
| `.audit/evidence.json` | JSON object with `files` array | forensic-mcp, air CLI | Both |
| `.audit/approvals.jsonl` | JSONL, one record per line | air CLI only | Both |
| `.audit/evidence_access.jsonl` | JSONL, one record per line | Both | Both |
| `.audit/exec.jsonl` | JSONL, one record per line | air CLI only | Both |
| `CASE.yaml` | YAML metadata | forensic-mcp | Both |
| `ACTIONS.md` | Markdown log | Both | Human |
| `FINDINGS.md` | Markdown findings | forensic-mcp | Human |

## Testing

20 tests across 3 test files:

| File | Tests | Coverage |
|------|-------|----------|
| `test_identity.py` | 3 | Identity resolution priority chain |
| `test_approve_reject.py` | 8 | Approve/reject workflows, audit log, edge cases |
| `test_case_io.py` | 9 | Case dir resolution, findings/timeline I/O, approval log |
