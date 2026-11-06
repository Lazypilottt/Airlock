"""Incremental Server-Sent Events parsing that keeps every event's original bytes.

The HTTP proxy re-emits events it does not change byte for byte, so it needs
the raw block next to the parsed fields. Field handling follows the HTML
standard's event-stream interpretation: ``data`` lines are joined with ``\\n``,
a leading space after the colon is dropped, comment lines start with ``:``.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

_BLOCK_END = re.compile(rb"\r\n\r\n|\n\n|\r\r|\r\n\n|\n\r\n")
_LINE = re.compile(rb"\r\n|\r|\n")


@dataclass(frozen=True)
class SSEEvent:
    """One dispatched event: its fields and the exact bytes it arrived as."""

    raw: bytes
    data: str | None = None
    event: str | None = None
    id: str | None = None
    retry: str | None = None


def parse_block(raw: bytes) -> SSEEvent:
    data_lines: list[str] = []
    fields: dict[str, str] = {}
    for line in _LINE.split(raw):
        if not line or line.startswith(b":"):
            continue
        name, _, value = line.partition(b":")
        if value.startswith(b" "):
            value = value[1:]
        key = name.decode("utf-8", errors="replace")
        text = value.decode("utf-8", errors="replace")
        if key == "data":
            data_lines.append(text)
        elif key in {"event", "id", "retry"}:
            fields[key] = text
    return SSEEvent(
        raw=raw,
        data="\n".join(data_lines) if data_lines else None,
        event=fields.get("event"),
        id=fields.get("id"),
        retry=fields.get("retry"),
    )


class SSEParser:
    """Feed bytes in, get complete events out; a size limit guards memory."""

    def __init__(self, max_event_bytes: int = 4 * 1024 * 1024) -> None:
        self.max_event_bytes = max_event_bytes
        self._buffer = b""

    def feed(self, chunk: bytes) -> Iterator[SSEEvent]:
        self._buffer += chunk
        while True:
            match = _BLOCK_END.search(self._buffer)
            if match is None:
                if len(self._buffer) > self.max_event_bytes:
                    raise ValueError("SSE event exceeds the size limit")
                return
            raw = self._buffer[: match.end()]
            self._buffer = self._buffer[match.end() :]
            yield parse_block(raw)

    def close(self) -> SSEEvent | None:
        """An unterminated trailing block, if any (dispatched as-is)."""
        rest, self._buffer = self._buffer, b""
        return parse_block(rest) if rest.strip() else None


def encode_event(data: str, event: str | None = None, id: str | None = None) -> bytes:
    """Serialise an event; every data line gets its own ``data:`` field."""
    lines: list[str] = []
    if event is not None:
        lines.append(f"event: {event}")
    if id is not None:
        lines.append(f"id: {id}")
    lines.extend(f"data: {line}" for line in data.split("\n"))
    return ("\n".join(lines) + "\n\n").encode("utf-8")


__all__ = ["SSEEvent", "SSEParser", "encode_event", "parse_block"]
