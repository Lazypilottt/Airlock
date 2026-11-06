# Known issues

These are explicit limitations of the current release and are not silently
treated as implemented features.

## Outbound policy layers

The default engine (`airlock.engine_factory.build_engine`) runs taint tracking
the policy engine (the bundled default policy unless `policy:` is set) and the
honeytoken check.

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

`attack` and `dashboard` are placeholders.

## `airlock serve`

- Tokens pass through unchanged, so static bearer tokens work. OAuth flows
  that discover the authorization server through the endpoint URL see the
  local proxy URL as the resource, which some servers reject; point those
  clients at the server directly until this is handled.
- A `notifications/tools/list_changed` is passed on to the client, which
  re-lists the tools through the proxy (where rug pulls are caught). Unlike
  stdio mode, Airlock does not re-list on its own.
- Every request through one `airlock serve` process shares one engine
  session (taint is tracked across all its servers), except legacy clients
  that send `Mcp-Session-Id`, which get one session each.
- JSON-RPC batches are refused (removed from the protocol in 2025-06-18), so
  every call stays inspectable.

## `airlock init`

- Configs must be plain JSON. A file with comments is reported as invalid and
  left untouched.
- `uninstall` restores the most recent backup, so edits made to the client
  config after `init` are lost (it asks first). Without a backup it unwraps in
  place.
- To change the mode of already-wrapped servers, run `uninstall`, then `init`
  again with the new `--mode`.
- The wrapped command is the absolute path of the `airlock` executable that
  ran `init`; moving or deleting that environment breaks the wrapped servers
  until `init` is run again from the new one.

## Honeytokens and the trifecta warning

- Honeytokens are matched literally after decoding (base64, hex, URL
  encoding, HTML entities). A token that is split, reversed or re-encoded in
  another way is not caught.
- A honeytoken hit follows the mode: in shadow mode the call goes through, but
  the alert and the stderr warning still fire.
- The trifecta check runs when a wrapped server lists its tools. Clients
  start servers at about the same time, so the first servers to list may not
  see the others yet; a server listed later reports it. Servers not seen for
  seven days drop out of a client's toolset.
- Two running copies of the same client (same `clientInfo.name`) count as one
  toolset.

## Slack approvals and OpenTelemetry

- The Slack Socket Mode connection (`SocketModeTransport`) is written from
  Slack's documentation and the `slack_sdk` API but has not been run against
  a real workspace yet; the approval flow is tested with a mocked Slack.
- Slack and the terminal are alternatives: with `slack.channel` set, ASK goes
  to Slack only.
- The OTLP setup (`setup_otlp`) needs the `otel` extra; without it Airlock
  warns and runs without telemetry. Spans are emitted per decision (calls and
  results, including approval rows).

## Auto-labelling

- Both providers are tested with mocks only; neither has been called for real
  here (no API key, and the `anthropic` SDK is an optional extra).
- A fooled labeller can still *add* wrong labels (more ASKs, no silent
  bypass); it cannot remove labels the heuristic found. Labels for tools the
  heuristic misses entirely depend on the model resisting the description.
- Proposals below `min_confidence` are stored but not applied.

## Terminal approvals

- Approvals need a controlling terminal. MCP servers started by desktop apps
  have none, so every `ask` is denied there (and the reason says so).
- A full-screen terminal client reads the same terminal. Airlock accepts a
  single key when the terminal is in raw mode, but the client may consume the
  keystroke first.
- The Windows console path is implemented but untested.
- A call cancelled by the client while its approval prompt is open is still
  forwarded if you then approve it.

## Benchmark

- **No honeytokens in AgentDojo data.** Planting them would mean adding
  values to the suites' environments (inboxes, files, accounts). AgentDojo's
  utility and security checks compare the environment before and after a
  task, and some user tasks count or search those items, so planted values
  could change task outcomes. The `airlock-flow` and `airlock-full`
  configurations still run the honeytoken check; it simply has nothing to
  find.
- **ASK is a block.** Benchmarks have no human; the results count ASK
  separately (`calls_asked`) so its share is visible.
- **Before 0.2 the adapter registered tools one at a time,** which left every
  tool after the first pending and denied. Numbers from that adapter are not
  comparable; none were published.

## Limits

Found while trying to get tainted data and honeytokens past Airlock (v0.2
review). These are caught, with regression tests in `tests/test_review.py`:
a value split across arguments or inside one argument, spaced out, upper-cased,
base64, base32, hex, URL-encoded, ROT13, reversed, an email spelled
`alice [at] evil [dot] example`, and data written through an intermediate tool
and then sent by reference (a file id returned for tainted data). These are
not:

- **Paraphrase and summarisation.** Matching is lexical. An agent that
  rewrites a value in its own words, or sends a summary of a secret document,
  is not caught.
- **Stacked encodings.** Each decoding view undoes one layer. ROT13 of base64,
  base64 of a reversed string, a custom cipher, spelling digits out as words:
  not caught.
- **Short values split across arguments.** The joined-arguments scan only
  reassembles long tokens and API keys; an email address or phone number
  split across fields is not reassembled.
- **References other than ids.** Derived taint follows `id` / `*_id` fields
  returned for a call that carried tainted data, and only matches when an
  argument is exactly that id. A file name, path or URL to the written data
  is not followed.
- **Taint across separately wrapped servers.** Each `airlock wrap` process has
  its own taint table (see the Task 11 open question); one `airlock serve`
  shares one table across all its remote servers.
- **Labels decide what is checked.** A tool that reads secrets but is not
  labelled `source_secret` (by a pack, the name heuristic or your config)
  taints nothing.
- **Expiry.** Taint entries expire after `taint.ttl_seconds` (default one
  hour) and the table keeps at most `taint.max_entries` values.
