# Contributing

## Development setup

```bash
uv sync
uv run pytest
uv run ruff check . && uv run ruff format --check .
uv run mypy airlock
uv run airlock attack --sdk
```

All of these must pass before a pull request is merged. Keep changes small
and add tests with the code.

## Adding a rule to a rule pack

Rules live in `packs/rules/core-v1.yaml`:

```yaml
- {id: my-rule-id, description: What it catches, pattern: 'regex', applies_to: both, severity: high, score: 0.85}
```

- `applies_to`: `result`, `description` or `both`.
- `score`: at or above `block_above` (0.85) blocks, at or above `redact_above`
  (0.5) redacts.
- Add a positive and a negative example to `tests/test_detect.py`, and run
  `uv run python -m bench.false_positives` to check the false-positive rate
  did not go up (report the before and after numbers in the pull request).

## Adding a label pack

Label packs tell Airlock which tools read untrusted content
(`source_untrusted`), read secrets (`source_secret`) or send data out
(`sink`), and which arguments carry data out:

```yaml
# packs/labels/my-server.yaml
name: my-server
description: The my-server MCP server
source: https://github.com/example/my-server
servers: ["my-server", "*my-server*"]
tools:
  - tool: send_message
    labels: [sink]
    args: {channel: destination, text: content}
  - tool: read_inbox
    labels: [source_untrusted]
```

Check tool names against the server's own documentation and say where you
checked them in a comment at the top. `airlock tools export-pack <server>`
writes a pack from labels you reviewed with `airlock tools review`. Add a test
in `tests/test_labels.py` that resolves a few of the tools.

## Adding a test

Tests live in `tests/`. End-to-end tests start real servers through
`airlock wrap` (see `tests/test_policy.py`) or `airlock serve`
(`tests/test_http.py`); use the fake server in `tests/fixtures/fake_server.py`
and a `tmp_path` data directory, and set `approvals: {terminal: false}` so a
test never waits for a human.

## Reporting false positives and bypasses

Use the issue templates. For a vulnerability in Airlock itself, see
`SECURITY.md`.
