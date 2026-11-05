# Known issues before v0.1

These are explicit limitations of the current release and are not silently
treated as implemented features.

## Missing outbound policy layers

The default engine currently has no policy, taint-tracking, or honeytoken
checks. Registry approval and the configured pluggable checks are the only
outbound controls. A deployment that requires sink-tool protection must add
those checks before production use.

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
