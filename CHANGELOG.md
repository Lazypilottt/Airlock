# Changelog

## 1.0.0 - 2026-11-07

### Added

- Classifier tooling: dataset builder with licence-checked public sets,
  synthetic indirect injections (English, Spanish, Hindi, obfuscated) and
  hard negatives, AgentDojo strings kept out; training and int8 export
  script for a GPU notebook; `classifier: airlock-v1 | promptguard-22m |
  promptguard-86m`.
- Python SDK (`airlock.sdk`): `Airlock`, sessions with trusted user prompts,
  `@firewall.tool` / `wrap_tool` for sync and async functions; examples for
  a plain OpenAI-compatible loop and PydanticAI.
- Slack approvals over Socket Mode (tokens from the environment, approver
  identity in the audit log) and OpenTelemetry spans and counters.
- Auto-labelling of unknown tools (Anthropic or any OpenAI-compatible
  endpoint; description treated as untrusted; proposals can only add
  labels), `airlock tools review` and `airlock tools export-pack`.
- `airlock dashboard`: local web UI (timeline with live updates, decision
  detail, false-positive feedback, taint flow view, tools, report), 127.0.0.1
  only, one-time link.
- `airlock attack`: red-team report card (`--sdk`, automated) and a guided
  client mode, with a local malicious test server and canary.
- Evaluation: benign false-positive set, latency per layer and end to end,
  `docs/evaluation.md`, `docs/threat-model.md`, `docs/demo-script.md`.
- Packaging: release workflow with PyPI trusted publishing, Dockerfile
  (non-root), `CONTRIBUTING.md`, `SECURITY.md`, issue templates.

### Changed

- The runtime `classifier` extra no longer pulls `optimum`; exporting a model
  uses the separate `classifier-export` extra (in its own environment).
- `exfil-long-query` and `exfil-markdown-image` now need a single long
  parameter value (README badge links were blocked).

### Fixed

- Secret masking missed prefixed variable names (`OPENAI_API_KEY=`), vendor
  key formats (`sk-`, Slack, Google, JWT) and random high-entropy strings
  in log previews.
- The stdio proxy's fallback engine (used only when no engine is passed) now
  comes from the default factory.
- The source distribution is built from an explicit list of paths.

### Security

- Dependency audit against OSV: no known vulnerabilities in the runtime
  dependencies; `transformers` 4.57.x (11 advisories) is confined to the
  build-time `classifier-export` extra, which `optimum` still requires.

## 0.2.0 - 2026-11-06

### Added

- Tool labels (`source_untrusted`, `source_secret`, `sink`, argument roles)
  from label packs (filesystem, fetch, GitHub, Slack, Playwright, AgentDojo),
  user overrides and a name heuristic; shown in `airlock tools list`.
- Per-session taint tracking: values read from untrusted or secret sources
  are recognised in later calls, including encoded, transformed, split and
  derived forms (ids returned for tainted data).
- Policy engine: ordered YAML rules (`tool`, `server`, `labels`, `direction`,
  `arg` conditions, `arg_tainted_by`, `result_score_above`, `quarantined`),
  a bundled default policy, hot reload, `airlock policy check` and
  `airlock policy test`.
- Terminal approvals for `ask` verdicts on the controlling terminal, with
  timeout, "allow for this session" and safe rendering of untrusted text.
- Honeytokens: `airlock honeytokens create/list`, decoy files, and a check
  that denies and alerts on any outgoing call carrying one.
- Lethal-trifecta warning across all servers of an MCP client.
- `airlock init` / `airlock uninstall` for Claude Desktop and Cursor
  (backups, idempotent, remote servers optional), shadow mode
  (`--mode shadow`) and `airlock report`.
- `airlock serve`: Streamable HTTP proxy (MCP 2026-07-28 and earlier
  revisions) with the same checks as stdio.
- Benchmark configurations `airlock-flow` and `airlock-full`, AgentDojo label
  pack, ASK counted separately.

### Changed

- With a policy loaded, taint hits, detector scores and quarantine status are
  evidence for the policy instead of verdicts of their own; rule names appear
  in decisions and the audit log.
- Audit store gains an `alerts` table (honeytokens, trifecta).

### Fixed

- Benchmark adapter listed tools one at a time, leaving all but the first
  pending and denied.
- Benchmark report inverted the attack success rate (AgentDojo's `security`
  is True when the attack succeeded).

### Security

- Review bypasses closed: values split across arguments or spaced out,
  base32, ROT13, reversed, spelled-out email addresses, data sent by
  reference through an intermediate tool; honeytokens split, reversed or
  re-encoded. Remaining limits are listed in `docs/known-issues.md`.

## 0.1.0 - 2026-11-06

### Added

- Transport-agnostic MCP engine with tool registry hash pinning and quarantine.
- L0/L1 normalization and rule-pack detection, with optional Prompt Guard L2.
- Tool-result redaction, blocking, structured-content handling, and spotlight
  marking.
- Stdio wrapping, audit logging with secret masking, CLI tool inspection, and
  AgentDojo benchmark harness.

### Security hardening

- Reject malformed JSON-RPC requests instead of forwarding or crashing.
- Drop malformed or oversized server output before it reaches protocol stdout.
- Fail closed on malformed tool definitions during discovery.
- Bound and secret-mask tool-definition diffs written to stderr.
