# Changelog

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
