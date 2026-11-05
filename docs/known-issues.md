# Known issues before v0.1

These are explicit limitations of the current release and are not silently
treated as implemented features.

## Outbound policy layers

The default engine (`airlock.engine_factory.build_engine`) runs taint tracking
on calls to tools labelled `sink`. It does not yet run the policy engine or the
honeytoken check (planned for v0.2).

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

`serve`, `init`, `policy`, `honeytokens`, `report`, and `uninstall` are
placeholders. Use `wrap`, `tools`, and `logs` for the currently implemented
CLI surface.
