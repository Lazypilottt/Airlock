"""Load a policy file once, then reload it when the file changes."""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Callable
from pathlib import Path

from airlock.policy.schema import CompiledPolicy, Policy, PolicyError
from airlock.resources import packs_dir

_Signature = tuple[int, int, int]


def default_policy_path() -> Path:
    """The bundled ``packs/policies/default.yaml``."""
    return packs_dir() / "policies" / "default.yaml"


def _warn(message: str) -> None:
    # stdout belongs to the MCP protocol in stdio mode.
    sys.stderr.write(f"airlock: {message}\n")
    sys.stderr.flush()


class PolicySource:
    """A compiled policy that follows its file.

    The file is compiled once at load. :meth:`current` re-checks the file's
    signature (inode, size, mtime) at most every ``check_interval`` seconds and
    recompiles when it changed. A reload that fails keeps the previous policy
    and reports the error, so a half-saved or invalid edit never disables
    enforcement. The initial load raises :class:`PolicyError` instead.
    """

    def __init__(
        self,
        path: Path | str,
        *,
        check_interval: float = 1.0,
        on_error: Callable[[str], None] = _warn,
    ) -> None:
        self.path = Path(path).expanduser()
        self.check_interval = check_interval
        self.on_error = on_error
        self.reloads = 0
        self.last_error: str | None = None
        self._signature = self._stat()
        if self._signature is None:
            raise PolicyError(f"Policy file not found: {self.path}")
        self._compiled = CompiledPolicy(Policy.load(self.path), origin=str(self.path))
        self._checked_at = time.monotonic()

    @property
    def policy(self) -> Policy:
        return self._compiled.policy

    def _stat(self) -> _Signature | None:
        try:
            stat = os.stat(self.path)
        except OSError:
            return None
        return (stat.st_ino, stat.st_size, stat.st_mtime_ns)

    def current(self) -> CompiledPolicy:
        """The compiled policy, reloaded first if the file changed."""
        now = time.monotonic()
        if now - self._checked_at >= self.check_interval:
            self._checked_at = now
            self.reload_if_changed()
        return self._compiled

    def reload_if_changed(self) -> bool:
        """Recompile if the file changed; return ``True`` when a new policy is active."""
        signature = self._stat()
        if signature is None:
            if self.last_error is None or "not found" not in self.last_error:
                self._fail(f"policy file {self.path} is missing; keeping the previous policy")
            return False
        if signature == self._signature:
            return False
        try:
            policy = Policy.load(self.path)
        except PolicyError as exc:
            # Remember the bad signature so the same broken file is reported once.
            self._signature = signature
            self._fail(f"{exc}; keeping the previous policy")
            return False
        self._signature = signature
        self._compiled = CompiledPolicy(policy, origin=str(self.path))
        self.reloads += 1
        self.last_error = None
        return True

    def _fail(self, message: str) -> None:
        self.last_error = message
        self.on_error(message)


class StaticPolicy:
    """A policy that never reloads (SDK callers and tests that build one in code)."""

    def __init__(self, policy: Policy, origin: str = "<in memory>") -> None:
        self._compiled = CompiledPolicy(policy, origin=origin)
        self.path: Path | None = None

    @property
    def policy(self) -> Policy:
        return self._compiled.policy

    def current(self) -> CompiledPolicy:
        return self._compiled


__all__ = ["PolicySource", "StaticPolicy", "default_policy_path"]
