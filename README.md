# Airlock

A transparent, low-latency firewall for AI agents using Model Context Protocol (MCP) tools.

## What it is

Airlock sits between an MCP client (such as Cursor or custom agent harnesses) and MCP servers as a transparent security proxy. It inspects and governs both outbound tool invocations and inbound tool execution results, protecting agents against prompt injection, data exfiltration, tool rug pulls, and unauthorized actions.

- **Outbound protection**: Evaluates policy rules, tracks sensitive data taint flowing toward sink tools (e.g., email, HTTP, shell), and verifies honeytokens.
- **Inbound protection**: Normalizes hidden or obfuscated text (Unicode smuggling, Base64 payloads, HTML comment inject ions), runs multi-tiered detector cascades, and safely redacts or blocks malicious tool outputs.
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

Install and initialize a local data directory:

```bash
uv pip install -e .
mkdir -p ~/.config/airlock
```

Wrap an MCP server. Everything after `--` is passed to the server; stdout
remains reserved for MCP JSON-RPC:

```bash
uv run airlock wrap --name my-server -- python -m my_mcp_server
```

Inspect registered tools and approve a pending tool:

```bash
uv run airlock tools list
uv run airlock tools approve my-server fetch
```

Inspect recent decisions (previews are secret-masked):

```bash
uv run airlock logs --since 1h
uv run airlock logs --verdict DENY --json
```

Use `--config path/to/airlock.yaml` with each command to select a
configuration file.

### Set up your MCP clients

`airlock init` finds the Claude Desktop and Cursor MCP configs, lists the
servers it will wrap, asks, writes a timestamped backup next to each file and
rewrites every local (stdio) server to run through `airlock wrap`, keeping its
`env`. Remote HTTP servers are listed and skipped. Running it again changes
nothing. It also offers a commented starter config at
`~/.config/airlock/airlock.yaml` (never over an existing one).

```bash
uv run airlock init                           # both apps, asks first
uv run airlock init --mode shadow             # log only for a trial period
uv run airlock init --config-path .cursor/mcp.json
uv run airlock uninstall                      # restore the backup (or unwrap in place)
```

Config locations: Claude Desktop uses
`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS),
`%APPDATA%\Claude\claude_desktop_config.json` (Windows) or
`~/.config/Claude/claude_desktop_config.json` (Linux); Cursor uses
`~/.cursor/mcp.json`. Restart the app after `init` or `uninstall`.

### Shadow mode and reports

In shadow mode (`mode: shadow`, `airlock wrap --mode shadow` or
`airlock init --mode shadow`) every call and result goes through and Airlock
records what it would have done. `airlock report` summarises a period:

```bash
uv run airlock report --since 7d
uv run airlock report --since 30d --format markdown > airlock-report.md
```

It covers decisions by verdict, the rules that fired, what shadow mode would
have stopped, quarantined tools, lethal-trifecta warnings and honeytoken
alerts.

### Policies and approvals

A policy is an ordered list of rules; the first rule whose conditions all hold
decides the verdict (`allow`, `deny`, `redact` or `ask`). Taint hits, detector
scores and quarantine status are evidence that rules turn into verdicts. With
no `policy:` in `airlock.yaml`, `airlock wrap` enforces the bundled
[`packs/policies/default.yaml`](packs/policies/default.yaml):

- deny sink arguments that carry a value read from a secret source;
- ask before sink arguments carry a value read from an untrusted source;
- block tool results at or above `block_above`, redact them at or above `redact_above`;
- block tools whose definition changed since approval (quarantined).

```yaml
# my-policy.yaml
default: allow
rules:
  - name: corp-mail-is-fine
    when: {tool: send_email, arg: {path: to, domain_in: [mycorp.example]}}
    then: allow
  - name: ask-untrusted-to-sinks
    when: {labels: [sink], arg_tainted_by: untrusted}
    then: ask
    message: Data from a web page is about to leave.
```

Conditions: `tool` and `server` (globs), `labels` (`any`/`all`), `direction`
(`call`/`result`), `arg` (`path` plus `domain_in`, `domain_not_in`,
`max_length` or `matches`), `arg_tainted_by` (`untrusted`/`secret`),
`result_score_above` (a number, `redact_above` or `block_above`) and
`quarantined`. Point `policy:` in `airlock.yaml` at your file; it is reloaded
when it changes, and an invalid edit keeps the previous policy.

```bash
uv run airlock policy check my-policy.yaml       # validate and explain each rule
uv run airlock policy test my-policy.yaml --event examples/policy-event.json
```

An `ask` verdict in stdio mode is put to you on the controlling terminal
(`/dev/tty`; the console on Windows), because stdin and stdout carry the MCP
protocol. Answer `y` (once), `s` (for the rest of the session) or `n`. No
answer within `approvals.timeout_seconds` (default 30) denies the call, and so
does the absence of a terminal, which is the case when a desktop app launches
the server. `approvals: {terminal: false}` turns every `ask` into a deny.

### Honeytokens

Honeytokens are fake secrets planted where a compromised agent would look.
Airlock denies any outgoing call that carries one, plain or base64-, hex- or
URL-encoded, writes a high-severity alert to the audit log and prints a loud
warning on stderr. No policy rule can allow it.

```bash
uv run airlock honeytokens create                      # AWS key pair, GitHub token, DB password, canary URL
uv run airlock honeytokens create --write ~/decoy/.env --write ~/decoy/.aws/credentials
uv run airlock honeytokens list
```

The tokens are invalid by construction: the AWS key ID contains a character
real key IDs never use, the GitHub token has a wrong checksum, and the
password and canary URL point at `127.0.0.1`. Decoy files start with a comment
saying they are fake, are created owner-only, and are never written over an
existing file; Airlock asks before writing each one (`--yes` skips the
question). Running `airlock wrap` processes pick up new tokens within a second.

### Lethal-trifecta warning

An agent that can read untrusted input, read private data and send data out
can be steered into leaking that data. Each `airlock wrap` process records
which MCP client it serves (the `clientInfo.name` from `initialize`) in the
shared registry, so the check covers all of that client's servers. When all
three legs are present, Airlock warns on stderr, naming the tools on each leg,
and `airlock tools list` shows the warning.

### Optional Prompt Guard 2 classifier

The L2 classifier is optional and is unavailable until the gated Meta model
has been authorized. Accept Meta's Llama license on Hugging Face, set
`HF_TOKEN`, install the classifier extras, and export either model:

```bash
uv pip install -e '.[classifier]'
export HF_TOKEN=...
python scripts/export_promptguard.py --variant 22M
# Use --variant 86M for the larger model.
```

Models are stored under `data_dir/models/`. By default, a missing classifier
is logged once and L0/L1 continue; require it with:

```yaml
classifier:
  required: true
  cache_size: 1024
```

The benchmark can be run with `python -m bench.latency`.

### AgentDojo benchmark harness

Install the optional harness with `uv pip install -e '.[bench]'`. Run a cheap
smoke benchmark with five tasks:

```bash
python -m bench.run --config none --model gpt-4o-mini-2024-07-18 --suites workspace --limit 5
python -m bench.run --config promptguard --model gpt-4o-mini-2024-07-18 --suites workspace --limit 5
python -m bench.run --config airlock-detect --model gpt-4o-mini-2024-07-18 --suites workspace --limit 5
python -m bench.report bench/results/*.json
```

Hosted models require their provider credentials (`OPENAI_API_KEY` for the
example model). AgentDojo commonly makes one or more calls per task; its task
runner retries up to three times, so five tasks generally means roughly five
to fifteen model calls before extra tool-loop turns.

Result decisions use `redact_above: 0.5` and `block_above: 0.85` by default.
Thresholds can be overridden for a server or tool:

```yaml
redact_above: 0.5
block_above: 0.85
server_overrides:
  untrusted-search:
    block_above: 0.75
tool_overrides:
  fetch:
    redact_above: 0.4
spotlight: true
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
