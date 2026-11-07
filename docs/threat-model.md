# Threat model

## What Airlock protects

A user runs an AI agent (an MCP client such as Claude Desktop or Cursor, or
their own code through the SDK) that calls tools on MCP servers. The user's
data (files, mail, tokens, accounts) is reachable through those tools.
Airlock sits between the agent and the tools and decides, per call and per
result, whether to let it through, change it, ask the user, or stop it.

## Who the attacker is

1. **Content author.** Anyone who can put text where a tool will read it: a
   web page, an email, an issue, a document, a calendar invite, a review.
   Their goal is to get the agent to follow their instructions (prompt
   injection): exfiltrate data, take actions, mislead the user.
2. **Malicious or compromised MCP server.** Controls tool names,
   descriptions, schemas and results; can change them after the user approved
   the server (rug pull); can try to influence how other servers' tools are
   used (shadowing).
3. **Not in scope:** the user themselves, the model provider, someone with
   code execution on the user's machine, and a malicious MCP client.

## Assets

- Secrets the tools can read (API keys, tokens, credentials, private data).
- The user's accounts and the actions tools can take with them.
- Integrity of the agent's view of tools and results.
- The audit log (it records what happened).

## Defences and the attacks they address

| Attack | Defence | Where |
|---|---|---|
| Instructions in a tool result | L0 normalisation (hidden Unicode, HTML comments, base64), L1 rules, optional L2 classifier; redact or block | `airlock/detect/` |
| Data from untrusted or secret sources leaving through a sink | Taint tracking (encoded, split, transformed and derived values), policy rules, human approval | `airlock/taint/`, `airlock/policy/`, `airlock/approve/` |
| Planted secrets being sent out | Honeytokens: any outgoing call carrying one is denied and alerted | `airlock/honeytokens/` |
| Poisoned descriptions, rug pulls, shadowing | Hash pinning, description checks, quarantine of changed or flagged tools | `airlock/registry/` |
| A toolset that can read untrusted input, read secrets and send data out | Lethal-trifecta warning across all of a client's servers | `airlock/registry/trifecta.py` |
| Unknown tools | Label packs, user labels, name heuristic, optional auto-labelling (can only add labels) | `airlock/registry/labels.py`, `autolabel.py` |
| Tampering with Airlock's own surfaces | Approval prompts escape control characters; the dashboard binds to 127.0.0.1 with a one-time token, CSRF and Host checks; the HTTP proxy validates `Origin` | `airlock/approve/`, `airlock/dashboard/`, `airlock/transport/http.py` |

## Trust assumptions

- The agent and MCP client honour Airlock's answers (a blocked call is not
  retried around it). Airlock only sees traffic that goes through it.
- The user's own prompt is trusted (SDK sessions mark its values as trusted).
- Labels are right: a secret source that nobody labelled `source_secret`
  taints nothing.
- Configuration and policy files are written by the user; Airlock does not
  defend against someone who can edit them.
- Fail mode: `closed` by default, so an error or timeout in a check denies.

## What Airlock does not stop

See the Limits section of the README and `docs/known-issues.md`. In short:
paraphrased or summarised data, stacked encodings, attacks phrased in ways
the rules and classifier have not seen, misuse that stays inside one tool
(command injection inside a server), excessive tool permissions unless a
policy rule covers them, traffic that bypasses Airlock, and taint across
separately wrapped servers.

## Data handling

Everything stays on the machine by default. Network access happens only for
features the user turns on: the HTTP proxy (to the upstream it is told
about), Slack approvals, OpenTelemetry export, and auto-labelling (which
sends only a tool's name, description and schema). The audit log masks
secrets before writing; reasons never contain secret values.
