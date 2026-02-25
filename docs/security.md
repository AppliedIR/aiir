# Security Model

## Design Philosophy

AIIR runs on isolated forensic workstations behind firewalls. The primary security boundary is network isolation and VM/container isolation, not in-band command filtering. The controls described here are defense-in-depth measures within that boundary.

## Network Assumptions

All AIIR components are assumed to run on a private forensic network:

- Not exposed to incoming connections from the Internet
- Not exposed to untrusted systems
- Protected by firewalls on a trusted network segment
- Outgoing Internet connections are required for report generation (Zeltser IR Writing MCP) and optionally for threat intelligence (OpenCTI) and documentation (MS Learn MCP)

wintools-mcp must only be installed on dedicated forensic workstations. Never install on personal laptops, production systems, or machines containing data outside the scope of the investigation.

## Authentication

### Gateway (sift-gateway)

Bearer token authentication on all MCP and REST endpoints (health check excepted). Tokens use the `aiir_gw_` prefix with 24 hex characters (96 bits of entropy).

```text
Authorization: Bearer aiir_gw_a1b2c3d4e5f6a1b2c3d4e5f6
```

API keys map to examiner identities in `gateway.yaml`. The examiner name is injected into backend tool calls for audit attribution.

When installed with `--remote`, TLS is enabled with a local CA certificate.

### wintools-mcp

Bearer token authentication with `aiir_wt_` prefix. Generated during installation. Every request requires `Authorization: Bearer <token>`. The `--no-auth` flag is for development only.

## Execution Security

### sift-mcp (Linux)

- **Denylist**: Blocks destructive system commands (mkfs, dd, fdisk, shutdown, etc.)
- **subprocess.run(shell=False)**: No shell, no arbitrary command chains
- **Argument sanitization**: Shell metacharacters blocked
- **Path validation**: Kernel interfaces (/proc, /sys, /dev) blocked for input
- **rm protection**: Case directories protected from deletion
- **Output truncation**: Large output capped
- **Flag restrictions**: Certain tools have specific flag blocks (find blocks `-exec`/`-delete`, sed blocks `-i`, tar blocks extraction/creation, etc.)

Uncataloged tools can execute with basic response envelopes. Catalog enrollment is for FK enrichment, not access control.

### wintools-mcp (Windows)

- **Catalog allowlist**: Only tools defined in YAML catalog files can execute
- **Hardcoded denylist**: 20+ dangerous binaries blocked (cmd, powershell, pwsh, wscript, cscript, mshta, rundll32, regsvr32, certutil, bitsadmin, msiexec, bash, wsl, sh, msbuild, installutil, regasm, regsvcs, cmstp, control — including .exe variants)
- **subprocess.run(shell=False)**: No shell, no command chains
- **Argument sanitization**: Shell metacharacters, response-file syntax (`@filename`), dangerous flags, and output redirect flags all blocked
- **Output directory control**: Zimmerman tool wrappers hardcode the output directory; user-supplied flags cannot override it

The installer requires typing `security_hole` (or passing `-AcknowledgeSecurityHole`) as an intentional friction point.

## Human-in-the-Loop Controls

### Structural Approval Gate

All findings and timeline events stage as DRAFT. Only the aiir CLI (which requires a human at `/dev/tty`) can move them to APPROVED or REJECTED. There is no MCP tool for approval. The AI cannot bypass this mechanism.

### PIN Authentication

The `aiir approve` command requires PIN confirmation. PINs are set per examiner via `aiir config --setup-pin`.

### Provenance Enforcement

Findings must be traceable to evidence:

| Tier | Source | Trust Level |
|------|--------|-------------|
| MCP | MCP audit log | System-witnessed |
| HOOK | Claude Code hook log | Framework-witnessed |
| SHELL | `supporting_commands` parameter | Self-reported |
| NONE | No audit record | Rejected |

Findings with NONE provenance and no supporting commands are automatically rejected by a hard gate in `record_finding()`.

### Content Integrity

- SHA-256 hashes are computed when findings are staged
- Hashes are verified at approval time
- Cross-file verification compares hashes in `findings.json` against `approvals.jsonl`
- `aiir review --verify` detects post-approval tampering

### Claude Code Controls

When Claude Code is the LLM client, `aiir setup client --client=claude-code` deploys:

- **Kernel-level sandbox**: Restricts Bash writes to prevent unauthorized file modifications
- **PostToolUse audit hook**: Captures every Bash command and output to `audit/claude-code.jsonl`
- **Provenance enforcement**: Findings without an evidence trail are rejected
- **PIN-gated human approval**: Approval requires the examiner's PIN

## Adversarial Evidence

Evidence under analysis may contain attacker-controlled content designed to manipulate LLM analysis. Any text field in any artifact — filenames, event log messages, registry values, email subjects, script comments, file metadata — could contain adversarial instructions.

Defenses:

- **AGENTS.md rules**: Instruct the LLM to never interpret embedded text as instructions
- **data_provenance markers**: Every tool response tags output as untrusted
- **Discipline reminders**: Rotating forensic methodology reminders in every response
- **HITL approval gate**: The primary mitigation — humans review all findings

## Evidence Handling

Never place original evidence on any AIIR system. Only use working copies for which verified originals or backups exist.

Any data loaded into the system runs the risk of being exposed to the underlying AI provider. Only place data on these systems that you are willing to send to your AI provider. Treat all AIIR systems as analysis environments, not evidence storage.

### Evidence Integrity Measures

- Registered evidence files are set to read-only (chmod 444) as defense-in-depth
- SHA-256 hashes computed at registration, verified on demand
- Evidence access is logged to `evidence_access.jsonl`
- `aiir evidence lock` creates a bind mount for the evidence directory (requires sudo)

These are defense-in-depth measures. Proper evidence integrity depends on verified hashes, write blockers, and chain-of-custody procedures that exist outside this platform.

### Filesystem Requirements

- **ext4**: Recommended. Full permission support for read-only protection.
- **NTFS/exFAT**: Acceptable. File permission controls will be silently ineffective.
- **FAT32**: Discouraged. 4 GB file size limit.

## Audit Trail

Every MCP tool call is logged to a per-backend JSONL file in the case `audit/` directory:

```text
audit/
├── forensic-mcp.jsonl
├── case-mcp.jsonl
├── report-mcp.jsonl
├── sift-mcp.jsonl
├── forensic-rag-mcp.jsonl
├── windows-triage-mcp.jsonl
├── opencti-mcp.jsonl
├── wintools-mcp.jsonl
└── claude-code.jsonl          # PostToolUse hook (Claude Code only)
```

Each entry includes:
- Unique evidence ID (`{backend}-{examiner}-{date}-{seq}`)
- Tool name and arguments
- Timestamp
- Examiner identity
- Case identifier

Evidence IDs resume sequence numbering across process restarts.

## Responsible Use

This project demonstrates the capabilities of AI-assisted incident response. While steps have been taken to enforce human-in-the-loop controls, it is ultimately the responsibility of each examiner to ensure that their findings are accurate and complete. Ultimate responsibility rests with the human. The AI, like a hex editor, is a tool to be used by properly trained incident response professionals. Users are responsible for ensuring their use complies with applicable laws, regulations, and organizational policies.
