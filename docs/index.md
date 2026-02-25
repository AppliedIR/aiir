# AIIR Platform Documentation

AIIR (AI-Assisted Incident Response) is a forensic investigation platform that connects LLM clients to forensic tools through MCP (Model Context Protocol) servers. It enforces human-in-the-loop controls, maintains chain-of-custody audit trails, and enriches tool output with forensic knowledge.

## What AIIR Does

- Executes forensic tools (Zimmerman suite, Volatility, Sleuth Kit, Hayabusa, and more) through catalog-gated MCP servers
- Records findings, timeline events, and investigation reasoning with full audit trails
- Enforces human approval for all findings before they enter reports
- Enriches tool output with artifact caveats, corroboration suggestions, and discipline reminders from forensic-knowledge
- Generates IR reports using data-driven profiles with Zeltser IR Writing guidance

## Components

| Component | Purpose |
|-----------|---------|
| **sift-gateway** | HTTP gateway aggregating all SIFT-local MCPs behind one endpoint |
| **forensic-mcp** | Findings, timeline, evidence, TODOs, discipline rules (15 tools) |
| **case-mcp** | Case lifecycle, evidence management, export/import, audit (13 tools) |
| **report-mcp** | Report generation with 6 profile types (6 tools) |
| **sift-mcp** | Linux forensic tool execution with FK enrichment (6 tools) |
| **forensic-rag-mcp** | Semantic search across 23K+ forensic knowledge records (3 tools) |
| **windows-triage-mcp** | Offline Windows baseline validation (13 tools) |
| **opencti-mcp** | Read-only threat intelligence from OpenCTI (10 tools) |
| **wintools-mcp** | Windows forensic tool execution (7 tools, separate repo) |
| **aiir CLI** | Human-only case management, approval, reporting, evidence handling |
| **forensic-knowledge** | Shared YAML data package for tool guidance and artifact knowledge |

## Quick Start

```bash
# One-command install (SIFT workstation)
curl -sSL https://raw.githubusercontent.com/AppliedIR/sift-mcp/main/quickstart.sh | bash
```

Or step by step:

```bash
git clone https://github.com/AppliedIR/sift-mcp.git && cd sift-mcp
./sift-install.sh          # Install MCP servers + gateway
cd .. && git clone https://github.com/AppliedIR/aiir.git && cd aiir
./aiir-install.sh          # Install aiir CLI + configure client
```

## Documentation Guide

- [Getting Started](getting-started.md) — Installation, first case walkthrough, key concepts
- [User Guide](user-guide.md) — Investigation workflow, findings, timeline, reporting
- [Architecture](architecture.md) — System design, deployment topologies, protocol stack
- [CLI Reference](cli-reference.md) — All aiir CLI commands with options and examples
- [MCP Reference](mcp-reference.md) — Tools by backend with parameters and response formats
- [Deployment Guide](deployment.md) — Installation options, remote access, multi-examiner setup
- [Security Model](security.md) — Execution security, evidence handling, responsible use
