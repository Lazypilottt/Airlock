"""``data_dir/honeytokens.json``: the planted tokens and the decoy files written."""

from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from airlock.honeytokens.tokens import Honeytoken

STORE_VERSION = 1


class HoneytokenStoreError(Exception):
    """Raised when ``honeytokens.json`` cannot be read or written."""


@dataclass
class HoneytokenFile:
    tokens: list[Honeytoken] = field(default_factory=list)
    decoys: list[dict[str, Any]] = field(default_factory=list)


def store_path(data_dir: Path) -> Path:
    return data_dir / "honeytokens.json"


def load(path: Path) -> HoneytokenFile:
    """Read the store; a missing file is an empty store."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return HoneytokenFile()
    except (OSError, ValueError) as exc:
        raise HoneytokenStoreError(f"Cannot read {path}: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("tokens", []), list):
        raise HoneytokenStoreError(f"{path} is not a honeytoken store")
    try:
        tokens = [Honeytoken.from_record(item) for item in raw.get("tokens", [])]
    except (KeyError, TypeError, ValueError) as exc:
        raise HoneytokenStoreError(f"{path} has a malformed token: {exc}") from exc
    decoys = [item for item in raw.get("decoys", []) if isinstance(item, dict)]
    return HoneytokenFile(tokens=tokens, decoys=decoys)


def save(path: Path, data: HoneytokenFile) -> None:
    """Write atomically, readable by the owner only."""
    payload = {
        "version": STORE_VERSION,
        "tokens": [token.to_record() for token in data.tokens],
        "decoys": data.decoys,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".honeytokens-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


class WatchedHoneytokens:
    """The store's tokens, re-read when the file changes (checked at most once a second).

    Tokens created while ``airlock wrap`` is running are picked up without a
    restart. If the file becomes unreadable, the last good tokens stay active.
    """

    def __init__(self, path: Path, check_interval: float = 1.0) -> None:
        self.path = path
        self.check_interval = check_interval
        self.last_error: str | None = None
        self._signature: tuple[int, int, int] | None = None
        self._tokens: list[Honeytoken] = []
        self._checked_at = -float("inf")

    def tokens(self) -> list[Honeytoken]:
        now = time.monotonic()
        if now - self._checked_at < self.check_interval:
            return self._tokens
        self._checked_at = now
        try:
            stat = os.stat(self.path)
            signature: tuple[int, int, int] | None = (
                stat.st_ino,
                stat.st_size,
                stat.st_mtime_ns,
            )
        except OSError:
            signature = None
        if signature == self._signature:
            return self._tokens
        self._signature = signature
        if signature is None:
            return self._tokens
        try:
            self._tokens = load(self.path).tokens
            self.last_error = None
        except HoneytokenStoreError as exc:
            self.last_error = str(exc)
        return self._tokens


__all__ = [
    "HoneytokenFile",
    "HoneytokenStoreError",
    "WatchedHoneytokens",
    "load",
    "save",
    "store_path",
]
