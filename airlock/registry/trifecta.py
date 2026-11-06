"""The lethal trifecta: untrusted input, private data and a way out, in one toolset.

An agent that can read attacker-controlled text, read private data and send
data somewhere can be talked into leaking that data. The legs usually live on
different servers (fetch, filesystem, email), so the check runs across every
server the same MCP client uses, as recorded in the shared registry.
"""

from __future__ import annotations

from dataclasses import dataclass

from airlock.registry.labels import Label
from airlock.registry.store import ToolRegistry, labels_from_row

# A server not seen for a week is treated as removed from the client's config.
ROSTER_MAX_AGE = 7 * 24 * 3600.0


@dataclass(frozen=True)
class Trifecta:
    """The tools on each leg, as ``server.tool``."""

    client: str
    untrusted: tuple[str, ...]
    private: tuple[str, ...]
    sink: tuple[str, ...]

    def message(self, limit: int = 4) -> str:
        def names(tools: tuple[str, ...]) -> str:
            shown = ", ".join(tools[:limit])
            return shown + (f" and {len(tools) - limit} more" if len(tools) > limit else "")

        return (
            f"Lethal trifecta for client '{self.client}': together its servers can read "
            f"untrusted input ({names(self.untrusted)}), read private data "
            f"({names(self.private)}) and send data out ({names(self.sink)}). A prompt "
            "injection in the untrusted input could make the agent leak the private data. "
            "Keep the taint rules in your policy, or remove one leg."
        )


def find_trifecta(
    registry: ToolRegistry, client: str, max_age: float | None = ROSTER_MAX_AGE
) -> Trifecta | None:
    """The trifecta across ``client``'s servers, or ``None`` if a leg is missing.

    Only approved tools count: pending and quarantined tools cannot be called.
    """
    legs: dict[Label, list[str]] = {
        Label.SOURCE_UNTRUSTED: [],
        Label.SOURCE_SECRET: [],
        Label.SINK: [],
    }
    for server_id in registry.client_servers(client, max_age):
        for row in registry.list_tools(server_id=server_id):
            if row["status"] != "approved":
                continue
            for label in labels_from_row(row).labels:
                legs[label].append(f"{server_id}.{row['tool_name']}")
    if not all(legs.values()):
        return None
    return Trifecta(
        client=client,
        untrusted=tuple(sorted(legs[Label.SOURCE_UNTRUSTED])),
        private=tuple(sorted(legs[Label.SOURCE_SECRET])),
        sink=tuple(sorted(legs[Label.SINK])),
    )


__all__ = ["ROSTER_MAX_AGE", "Trifecta", "find_trifecta"]
