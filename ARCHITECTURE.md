# AIIR Platform Architecture

**Status:** Definitive reference for what is built. Not aspirational.
**Last updated:** 2026-02-21

---

## Invariants

These are structural facts. If a diagram, README, or plan contradicts any of these, the diagram is wrong.

1. **All client-to-server connections use MCP Streamable HTTP.** No client connects via stdio. Stdio is internal only (gateway → backend MCPs).
2. **The gateway runs on the SIFT workstation.** It is not optional — even solo analysts use it (on localhost). It aggregates all SIFT-local MCPs behind one HTTP endpoint.
3. **wintools-mcp runs on a Windows machine.** It is independent of the gateway. The gateway does not manage, proxy, or coordinate with wintools-mcp in any way.
4. **Clients connect to two endpoints at most:** the gateway (for all SIFT tools) and wintools-mcp (for Windows tools). These are separate, unrelated connections.
5. **The case directory lives on the SIFT machine.** forensic-mcp reads and writes it. The aiir CLI reads and writes it. In solo mode they share a local filesystem; in multi-examiner mode the case directory is exported via NFS or SMB.
6. **Human approval is structural.** Findings stage as DRAFT. Only the aiir CLI (human, interactive, /dev/tty) can move them to APPROVED or REJECTED. The AI cannot approve its own work.
7. **AGENTS.md is the source of truth for forensic rules.** It is LLM-agnostic. Per-client config files (CLAUDE.md, .cursorrules) are copies/derivatives, not sources.
8. **forensic-knowledge is a shared data package.** It is a pip-installable YAML package. forensic-mcp, sift-mcp, and wintools-mcp all depend on it. It has no runtime state.

---

## Components

### Where things run

| Component | Runs on | Port | Protocol (to clients) | Protocol (internal) |
|-----------|---------|------|-----------------------|---------------------|
| aiir-gateway | SIFT | 4508 | Streamable HTTP MCP | stdio to backends |
| forensic-mcp | SIFT | — | (via gateway) | stdio subprocess |
| sift-mcp | SIFT | — | (via gateway) | stdio subprocess |
| forensic-rag-mcp | SIFT | — | (via gateway) | stdio subprocess |
| windows-triage-mcp | SIFT | — | (via gateway) | stdio subprocess |
| opencti-mcp | SIFT | — | (via gateway) | stdio subprocess |
| wintools-mcp | Windows | 4624 | Streamable HTTP MCP | — |
| aiir CLI | SIFT | — | — (filesystem) | — |
| forensic-knowledge | anywhere | — | — (pip package) | — |

### What each component does

| Component | Purpose |
|-----------|---------|
| **aiir-gateway** | Aggregates SIFT-local MCPs. Starts each as a stdio subprocess. Exposes all their tools via `/mcp` (Streamable HTTP) and `/api/v1/tools` (REST). API key → examiner identity mapping for multi-user. |
| **forensic-mcp** | Case management, findings, timeline, evidence, TODOs, audit, discipline rules, reports. The investigation state machine. 48 tools. |
| **sift-mcp** | Catalog-gated forensic tool execution on Linux/SIFT. Zimmerman suite, Volatility, Sleuth Kit, Hayabusa, etc. FK-enriched response envelopes. 35 tools, 36 catalog entries. |
| **forensic-rag-mcp** | Semantic search across Sigma rules, MITRE ATT&CK, Atomic Red Team, Splunk, KAPE, Velociraptor, LOLBAS, GTFOBins. |
| **windows-triage-mcp** | Offline Windows baseline validation. Checks files, processes, services, scheduled tasks, registry, DLLs, pipes against known-good databases. |
| **opencti-mcp** | Threat intelligence from OpenCTI. IOC lookup, threat actor search, malware search, MITRE technique search. |
| **wintools-mcp** | Catalog-gated forensic tool execution on Windows. Zimmerman suite, Hayabusa. FK-enriched response envelopes. Denylist blocks dangerous binaries. 23 tools, 16 catalog entries. |
| **aiir CLI** | Human-only actions: approve/reject findings, review case status, manage evidence, execute forensic commands with audit trail, configure examiner identity. Not callable by AI. |
| **forensic-knowledge** | Pip-installable YAML data package. Tool guidance, artifact knowledge, discipline rules, playbooks, collection checklists. No runtime state. |

---

## Deployment Topologies

### Solo analyst

One SIFT workstation. The LLM client and aiir CLI both run on SIFT.

```
┌─────────────────────── SIFT Workstation ───────────────────────┐
│                                                                │
│  LLM Client ──streamable-http──► aiir-gateway :4508            │
│                                      │                         │
│                                    stdio                       │
│                                      │                         │
│                                  SIFT MCPs                     │
│                                      │                         │
│  aiir CLI ──filesystem──► Case Directory ◄── forensic-mcp ─────┘
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### SIFT + Windows

SIFT workstation + Windows forensic VM. The LLM client and aiir CLI run on SIFT. wintools-mcp runs on the Windows box and accesses the case directory over SMB. The LLM client makes two separate HTTP connections: one to the gateway (SIFT tools) and one to wintools-mcp (Windows tools).

```
┌─────────────────────── SIFT Workstation ───────────────────────┐
│                                                                │
│  LLM Client ──streamable-http──► aiir-gateway :4508 ──► MCPs  │
│                                                                │
│  aiir CLI ──filesystem──► Case Directory                       │
│                                                                │
└────────────────────────────────────────────────────────────────┘

┌───────────── Windows Forensic Workstation ─────────────────────┐
│                                                                │
│  wintools-mcp :4624                                            │
│       │                                                        │
│       └──SMB──► Case Directory (on SIFT)                       │
│                                                                │
└────────────────────────────────────────────────────────────────┘

LLM Client ──streamable-http──► wintools-mcp :4624
```

### Multi-examiner

Multiple examiners share a case. Each examiner runs their own full stack (LLM client, aiir CLI, aiir-gateway, and all MCPs) on their own SIFT workstation. The case directory lives on shared storage (NFS or SMB) so all examiners read and write the same case.

```
┌─ Examiner 1 — SIFT Workstation ─┐
│ LLM Client + aiir CLI            │
│ aiir-gateway :4508 ──► MCPs      │
│                                   │
└───────────────────────────────────┘
        │
        ▼
┌─ Shared Storage (NFS / SMB) ─────┐
│ Case Directory                    │
│   examiners/steve/                │
│   examiners/jane/                 │
└───────────────────────────────────┘
        ▲
        │
┌─ Examiner 2 — SIFT Workstation ─┐
│ LLM Client + aiir CLI            │
│ aiir-gateway :4508 ──► MCPs      │
│                                   │
└───────────────────────────────────┘
```

Each examiner writes to `examiners/{their-slug}/`. Reads merge all `examiners/*/` with scoped IDs. The shared case directory is exported via NFS or SMB so every examiner's stack sees the same state.

---

## Case Directory Structure

```
cases/INC-2026-0219/
├── CASE.yaml                    # Case metadata (name, mode, team list)
├── evidence/                    # Original evidence (read-only after registration)
├── extracted/                   # Tool output, working files
├── reports/                     # Generated reports
└── examiners/
    ├── steve/
    │   ├── findings.json        # DRAFT → APPROVED/REJECTED
    │   ├── timeline.json
    │   ├── todos.json
    │   ├── evidence.json
    │   ├── actions.jsonl         # Investigative actions (append-only)
    │   ├── evidence_access.jsonl # Chain-of-custody log
    │   ├── approvals.jsonl
    │   └── audit/
    │       ├── forensic-mcp.jsonl
    │       ├── sift-mcp.jsonl
    │       └── ...
    └── jane/
        └── (same structure)
```

---

## Protocol Stack

```
LLM Client
    │
    │  MCP Streamable HTTP (POST /mcp, SSE responses)
    │
    ▼
aiir-gateway :4508                     wintools-mcp :4624
    │                                      │
    │  stdio (subprocess)                  │  subprocess.run(shell=False)
    │                                      │
    ▼                                      ▼
forensic-mcp                          Windows forensic tools
sift-mcp ──► SIFT forensic tools      (Zimmerman, Hayabusa)
forensic-rag-mcp
windows-triage-mcp
opencti-mcp
```

The gateway uses the low-level MCP `Server` class (not FastMCP) because tools are discovered dynamically from backends at runtime. wintools-mcp uses `FastMCP.streamable_http_app()` because it has statically-registered tools.

Authentication at both endpoints uses ASGI-level wrappers (not Starlette `BaseHTTPMiddleware`) to avoid buffering SSE streams.

---

## Examiner Identity

Resolution order (highest priority first):

1. `--examiner` CLI flag
2. `AIIR_EXAMINER` environment variable
3. `~/.aiir/config.yaml` examiner field
4. `AIIR_ANALYST` environment variable (deprecated)
5. OS username (fallback, warns if unconfigured)

The gateway maps API keys to examiner identities in `gateway.yaml`. The examiner name is injected into forensic-mcp tool calls for audit trail attribution.

---

## Client Configuration

`aiir setup client` generates Streamable HTTP configs. All entries use `"type": "streamable-http"`.

```bash
# Solo (gateway on localhost)
aiir setup client --sift=http://127.0.0.1:4508 --client=claude-code -y

# SIFT + Windows
aiir setup client --sift=http://SIFT_IP:4508 --windows=WIN_IP:4624

# Interactive wizard
aiir setup client
```

Generated `.mcp.json` example:
```json
{
  "mcpServers": {
    "aiir": {
      "type": "streamable-http",
      "url": "http://127.0.0.1:4508/mcp"
    },
    "wintools-mcp": {
      "type": "streamable-http",
      "url": "http://192.168.1.20:4624/mcp"
    }
  }
}
```

---

## Repo Map

| Repo | GitHub | Purpose |
|------|--------|---------|
| [aiir](https://github.com/AppliedIR/aiir) | AppliedIR/aiir | CLI + this architecture doc |
| [forensic-mcp](https://github.com/AppliedIR/forensic-mcp) | AppliedIR/forensic-mcp | Case management MCP |
| [sift-mcp](https://github.com/AppliedIR/sift-mcp) | AppliedIR/sift-mcp | SIFT tool execution MCP |
| [wintools-mcp](https://github.com/AppliedIR/wintools-mcp) | AppliedIR/wintools-mcp | Windows tool execution MCP |
| [forensic-knowledge](https://github.com/AppliedIR/forensic-knowledge) | AppliedIR/forensic-knowledge | Shared YAML data package |
| [aiir-gateway](https://github.com/AppliedIR/aiir-gateway) | AppliedIR/aiir-gateway | HTTP gateway |
| [forensic-rag-mcp](https://github.com/AppliedIR/forensic-rag-mcp) | AppliedIR/forensic-rag-mcp | Knowledge search MCP |
| [windows-triage-mcp](https://github.com/AppliedIR/windows-triage-mcp) | AppliedIR/windows-triage-mcp | Windows baseline MCP |
| [opencti-mcp](https://github.com/AppliedIR/opencti-mcp) | AppliedIR/opencti-mcp | Threat intelligence MCP |

All repos are private under the AppliedIR GitHub org.
