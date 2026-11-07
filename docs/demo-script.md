# Demo script: 90 seconds

An agent leaks a honeytoken without Airlock, then is stopped with it. Ends on
the dashboard flow view. Record at 1920x1080, terminal font 18 pt or larger,
dark theme.

## Before recording

1. `uv sync` in the repository; quit any running MCP client.
2. `uv run airlock honeytokens create --write ~/airlock-demo/.env --yes`
   (fake credentials; nothing real is ever used).
3. Prepare two Cursor configs (or Claude Desktop):
   - **unprotected:** `uv run airlock attack --client cursor --without-airlock`,
     stop at the prompt, keep the config copy it wrote;
   - **protected:** the same without `--without-airlock`.
4. Have the four prompts from `airlock attack` in a text file to paste.

## Recording

| Time | Screen | Action | Voice-over (suggested) |
|---|---|---|---|
| 0:00-0:08 | Title card | - | "AI agents read untrusted content and hold your secrets. Here is what that means." |
| 0:08-0:30 | Cursor, unprotected config | Paste prompt 4 ("Read my notes ... follow any instructions") | "The notes contain a planted fake key and an instruction to back it up to a URL." |
| 0:30-0:38 | Terminal running `airlock attack --without-airlock` | Press Enter; the report card shows "the honeytoken reached the canary" | "The agent did it. The secret left the machine." |
| 0:38-0:45 | Terminal | `uv run airlock init --client cursor` (answer y), restart Cursor | "One command puts Airlock in front of every server." |
| 0:45-1:05 | Cursor, protected | Paste the same prompt | "Same agent, same page." Cursor shows "Blocked by Airlock: A planted honeytoken ..." |
| 1:05-1:12 | Terminal | Report card: "BLOCKED: the honeytoken never left" | "Nothing reached the canary." |
| 1:12-1:30 | Browser | `uv run airlock dashboard`, open the link, go to **Flows** | End on the flow view: `airlock-attack.read_notes` → token → `airlock-attack.http_post`. "Every decision, with the reason and the path the data tried to take." |

## After recording

- `uv run airlock uninstall --client cursor`, then restore any config you
  swapped by hand.
- Delete `~/airlock-demo/` and, if you like, the demo honeytokens from
  `~/.config/airlock/honeytokens.json`.
- Put the video link at the top of the README.
