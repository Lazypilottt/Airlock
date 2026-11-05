"""Locate data files bundled with Airlock (rule, label and policy packs)."""

from __future__ import annotations

from pathlib import Path

_PACKAGE_DIR = Path(__file__).resolve().parent


def packs_dir() -> Path:
    """Return the directory holding the bundled ``labels``, ``rules`` and ``policies`` packs.

    Wheels ship the repository's ``packs/`` directory as ``airlock/_packs`` (see
    ``pyproject.toml``); a source checkout uses ``packs/`` at the repository root.
    """
    bundled = _PACKAGE_DIR / "_packs"
    if bundled.is_dir():
        return bundled
    return _PACKAGE_DIR.parent / "packs"


__all__ = ["packs_dir"]
