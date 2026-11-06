# Changelog

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
