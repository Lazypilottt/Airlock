# Airlock

A transparent, low-latency firewall for AI agents using Model Context Protocol (MCP) tools.

## What it is

Airlock sits between an MCP client (such as Cursor or custom agent harnesses) and MCP servers as a transparent security proxy. It inspects and governs both outbound tool invocations and inbound tool execution results, protecting agents against prompt injection, data exfiltration, tool rug pulls, and unauthorized actions.

- **Outbound protection**: Evaluates policy rules, tracks sensitive data taint flowing toward sink tools (e.g., email, HTTP, shell), and verifies honeytokens.
- **Inbound protection**: Normalizes hidden or obfuscated text (Unicode smuggling, Base64 payloads, HTML comment injections), runs multi-tiered detector cascades, and safely redacts or blocks malicious tool outputs.
- **Tool Integrity**: Pins cryptographic hashes of tool definitions (name, description, schema) and quarantines tools with suspicious changes (rug pulls).
- **Audit & Forensics**: Records structured decisions and rationale into local SQLite storage, with support for both `shadow` (observation) and `enforce` (blocking) modes.

## Install

Prerequisites: Python >= 3.12 and [`uv`](https://docs.astral.sh/uv/).

Install from source or via uv:

```bash
uv pip install -e .
```

Or install the package:

```bash
uv pip install airlock-mcp
```

## Quick start

Check CLI capabilities:

```bash
uv run airlock --help
```

Initialize default configurations:

```bash
uv run airlock init
```

Run in proxy mode:

```bash
uv run airlock serve
```

## How it works

1. **Transport-Agnostic Core**: The core engine (`airlock.engine`) operates strictly on typed events and returns deterministic decisions (`allow`, `redact`, `block`, `quarantine`). Proxies (stdio, HTTP) and benchmark adapters layer on top of this engine without duplicating logic.
2. **Inbound Normalization & Detection Cascade**:
   - Level 1: Fast deterministic heuristic rules and regexes.
   - Level 2: Small local ONNX classification model.
   - Level 3 (Optional): Asynchronous LLM-as-a-judge for complex ambiguities.
3. **Outbound Taint Tracking & Policy Enforcement**: Prevents untrusted tool outputs or sensitive secrets from reaching sinks without explicit human or policy approval.
4. **Fail-Safe Operation**: If a check errors or exceeds the timeout budget, the configured `fail_mode` (`open` or `closed`) applies immediately while logging the incident.

## Benchmarks

Airlock is designed with a strict latency budget:
- **Budget**: Under 50 ms p95 added latency per tool call on standard laptop CPU hardware (excluding optional remote LLM judges).
- Validated against standardized security suites (such as AgentDojo) to evaluate attack detection accuracy with low false-positive rates.

## Limits

- Stdio proxy mode allocates `stdout` exclusively for JSON-RPC MCP protocol traffic. All diagnostic logs are routed to `stderr` or local log files.
- Offline-first: Airlock makes zero external network requests by default unless explicitly configured (e.g. external LLM judge).
- Local resource usage: High-throughput streaming environments should adjust `check_timeout_ms` to balance security inspection depth with real-time responsiveness.

## Contributing

We welcome contributions! Please see our guidelines:

1. Clone repository and install development dependencies:
   ```bash
   uv sync
   ```
2. Run linting, type checks, and tests:
   ```bash
   uv run ruff check .
   uv run ruff format --check .
   uv run mypy airlock
   uv run pytest
   ```
3. Set up pre-commit hooks:
   ```bash
   pre-commit install
   ```

## License

Apache-2.0
