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

### Remote (HTTP) servers

`airlock serve` puts Airlock in front of a remote Streamable HTTP MCP server:

```bash
uv run airlock serve --upstream https://mcp.example.com/mcp --listen 127.0.0.1:8765 --name example
```

Point the client at `http://127.0.0.1:8765/mcp`. The same checks as in stdio
mode apply to `tools/list` and `tools/call`; everything else, including
progress notifications on SSE streams, is streamed through as it arrives.
`Authorization`, session and protocol headers pass through unchanged, so
servers on the 2026-07-28 protocol and on earlier Streamable HTTP revisions
(sessions, GET streams) both work. Browser `Origin`s other than localhost are
refused (`--allow-origin` adds one).

`airlock init --remote` does this for you: it points each remote server in
the client config at its own local port and records the original URL, and a
bare `airlock serve` then runs all of them. Keep it running while the client
is open; `airlock uninstall` restores the original URLs.

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

### Python SDK (agents without MCP)

```python
from airlock.sdk import Airlock, AirlockBlocked

firewall = Airlock()  # same engine and policy as `airlock wrap`


@firewall.tool(labels=["source_untrusted"])
def fetch_page(url: str) -> str: ...


@firewall.tool(labels=["sink"], args={"to": "destination", "body": "content"})
def send_email(to: str, body: str) -> str: ...


with firewall.session(user_prompt=prompt):  # addresses the user typed are trusted
    page = fetch_page(url)
    send_email("bob@corp.example", summary)  # an address taken from `page` would be blocked
```

Sync and async functions both work; `firewall.wrap_tool(fn, labels=[...])`
guards an existing function. DENY raises `AirlockBlocked` (with `.reasons`),
or returns an error string with `Airlock(on_deny="return")`; REDACT runs the
tool with redacted arguments or returns the redacted result; ASK calls
`Airlock(approve=callback)` and is denied without one. Examples:
`examples/sdk_openai_loop.py` (a plain loop against any OpenAI-compatible
API) and `examples/sdk_pydantic_ai.py` (PydanticAI, one line).

### Approvals in Slack

Set a channel and Airlock asks there instead of on the terminal, with Approve
and Deny buttons (Socket Mode, so no public URL):

```yaml
slack:
  channel: C0123456789          # or #airlock-approvals
  timeout_seconds: 300          # no answer denies
  allowed_users: [U0ABCDEF]     # optional: who may answer
  # tokens are read from these environment variables, never from this file
  bot_token_env: AIRLOCK_SLACK_BOT_TOKEN   # xoxb-...
  app_token_env: AIRLOCK_SLACK_APP_TOKEN   # xapp-..., scope connections:write
```

Install with the `slack` extra. The message shows the tool, server, rule,
reasons and a masked argument preview; the answer, who gave it and when go to
the audit log.

### OpenTelemetry

```yaml
otel:
  enabled: true
  endpoint: http://localhost:4318   # OTLP/HTTP collector
```

With the `otel` extra, every decision becomes a span (`airlock.tool`,
`airlock.server`, `airlock.verdict`, `airlock.rule`, top scores, latency) and
increments the `airlock.decisions` counter by verdict.

### Auto-labelling unknown tools

Tools that no label pack or `labels:` entry covers get labels from the name
heuristic. With `auto_label` on, a model is also asked; only the tool's name,
description and input schema are sent.

```yaml
auto_label:
  enabled: true
  provider: anthropic            # or openai (any OpenAI-compatible endpoint)
  model: claude-opus-5-5         # required for openai
  api_key_env: ANTHROPIC_API_KEY # read from the environment
  min_confidence: 0.6
```

The description is treated as untrusted: it is JSON-escaped between
delimiters with a random nonce, and the answer must match a strict schema or
it is dropped. Proposals are cached by tool hash, applied as `proposed`, and
can only add labels to what the heuristic found. Review them, then share the
result:

```bash
uv run airlock tools review                  # accept, edit or reject
uv run airlock tools export-pack my-server -o packs/labels/my-server.yaml
```

The Anthropic provider uses the official SDK (`autolabel` extra); the
OpenAI-compatible one needs nothing extra.

### Dashboard

```bash
uv run airlock dashboard        # prints a one-time link on 127.0.0.1
```

A live timeline of decisions with filters, each decision's reasons, rule,
scores and masked previews, a flow view of stopped taint (source tool →
value → sink tool), the tools page with labels, hashes and approve buttons,
and the report. "Mark as false positive" saves the decision to
`data_dir/feedback/` for the next classifier training round. It listens on
127.0.0.1 only, needs the one-time link (then a strict session cookie), and
loads nothing from the internet.

### Red-team your setup (`airlock attack`)

**For testing your own setup only.** A local, deliberately malicious MCP test
server (`attack/server.py`) tries a poisoned tool description, injected tool
results (plain, hidden HTML, zero-width, base64), a rug pull, cross-server
shadowing, and an exfiltration lure. The only exfiltration target is a canary
listener on 127.0.0.1 and the only secret is a honeytoken.

```bash
uv run airlock attack --sdk                  # automated, no human: a report card in seconds
uv run airlock attack --client cursor        # guided run inside your own client
uv run airlock attack --client cursor --without-airlock   # the same, unprotected
```

`--sdk` runs every scenario against a scripted agent that obeys every
injection, once without Airlock and once with it, and exits non-zero if any
scenario gets through. `--client` writes a copy of your client config with the
test server added (your real config is never changed), gives you the prompts
to send, and builds the report card from the canary and the audit log.

### Choosing the classifier

The optional L2 classifier is Prompt Guard 2 by default. Airlock's own model,
trained on tool-output-style data, is selected with:

```yaml
classifier: airlock-v1          # or promptguard-22m (default), promptguard-86m
```

Models load from `data_dir/models/<name>/model.int8.onnx`. How to build the
dataset and train `airlock-v1` on a free GPU notebook: `docs/training.md`.

### AgentDojo benchmark harness

Install the optional harness with `uv pip install -e '.[bench]'`. Run a cheap
smoke benchmark with five tasks:

```bash
for config in none promptguard airlock-detect airlock-flow airlock-full; do
  python -m bench.run --config $config --model gpt-4o-mini-2024-07-18 --suites workspace --limit 5
done
python -m bench.report bench/results/*.json
```

Configurations, all built with the default engine factory:

| Config | What runs |
|---|---|
| `none` | no defence |
| `promptguard` | Prompt Guard 2 alone on tool results |
| `airlock-detect` | the L0/L1/L2 detector cascade on results, with the default policy |
| `airlock-flow` | taint tracking, the default policy and honeytokens on calls; no detectors |
| `airlock-full` | detectors and flow together |

Every tool call goes through `Engine.on_tool_call` before AgentDojo runs it:
DENY returns an error to the agent, and ASK (nobody answers approvals in a
benchmark) counts as DENY. The results file records Airlock's own counts
(`calls_denied`, `calls_asked`, `results_denied`, `results_redacted`, rules
fired). AgentDojo's tools are labelled by `packs/labels/agentdojo.yaml`. Each
run uses a fresh temporary data directory and approves the suite's tools on
first listing. Honeytokens are not planted in the suites' data: see
`docs/known-issues.md`.

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
