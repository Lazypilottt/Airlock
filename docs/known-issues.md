# Known issues before v0.1

These are explicit limitations of the current release and are not silently
treated as implemented features.

## Outbound policy layers

The default engine (`airlock.engine_factory.build_engine`) runs taint tracking
and the policy engine (the bundled default policy unless `policy:` is set). It
does not yet run the honeytoken check (planned for v0.2).

With a policy loaded, taint hits, detector scores and quarantine status only
become verdicts through rules. A custom policy that leaves out one of the
default rules removes that protection; `airlock policy check` warns about it.

Each `airlock wrap` process keeps its own taint table, so a value read through
one wrapped server and sent through a different wrapped server is not caught.
Flows within a single server are caught.

## Resource limits outside stdio

The stdio transport bounds individual JSON-RPC lines and pending requests, but
direct callers of the transport-agnostic engine can still submit very large
strings or deeply nested structured content. Applications embedding the engine
should enforce input-size and nesting limits at their event boundary.

## Optional classifier availability

Prompt Guard is optional and gated. Unless `classifier.required` is enabled,
missing or unloadable weights continue with L0 and L1 only. This is fail-open
with respect to the classifier, not an indication that the result is benign.

## Placeholder CLI commands

`serve`, `init`, `honeytokens`, `report`, and `uninstall` are placeholders.
Use `wrap`, `tools`, `policy` and `logs` for the currently implemented CLI
surface.

## Terminal approvals

- Approvals need a controlling terminal. MCP servers started by desktop apps
  have none, so every `ask` is denied there (and the reason says so).
- A full-screen terminal client reads the same terminal. Airlock accepts a
  single key when the terminal is in raw mode, but the client may consume the
  keystroke first.
- The Windows console path is implemented but untested.
- A call cancelled by the client while its approval prompt is open is still
  forwarded if you then approve it.
