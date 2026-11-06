"""Carry out a policy verdict on a payload."""

from __future__ import annotations

import copy
import re
from collections.abc import Iterable
from typing import Any

REDACTED_ARGUMENT = "[removed by Airlock]"

_PATH_PART = re.compile(r"([^.\[\]]+)|\[(\d+)\]")


def _replace_strings(value: Any) -> Any:
    if isinstance(value, str):
        return REDACTED_ARGUMENT
    if isinstance(value, dict):
        return {key: _replace_strings(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_strings(item) for item in value]
    return value


def _redact_path(arguments: dict[str, Any], path: str) -> None:
    parts = _PATH_PART.findall(path)
    if not parts:
        return
    parent: Any = arguments
    for name, index in parts[:-1]:
        try:
            parent = parent[int(index)] if index else parent[name]
        except (KeyError, IndexError, TypeError):
            return
    name, index = parts[-1]
    try:
        key: int | str = int(index) if index else name
        parent[key] = _replace_strings(parent[key])
    except (KeyError, IndexError, TypeError):
        return


def redact_arguments(arguments: dict[str, Any], paths: Iterable[str]) -> dict[str, Any]:
    """Return a copy of ``arguments`` with every string under ``paths`` replaced.

    ``*`` redacts every string. A path that does not resolve is skipped. A
    tainted dictionary key keeps its name; only its value is replaced.
    """
    redacted = copy.deepcopy(arguments)
    wanted = list(dict.fromkeys(paths))
    if "*" in wanted:
        result: dict[str, Any] = _replace_strings(redacted)
        return result
    for path in wanted:
        _redact_path(redacted, path)
    return redacted


def withheld_result(rule: str) -> dict[str, Any]:
    """A result payload that replaces the whole tool result."""
    return {
        "content": [
            {"type": "text", "text": f"[removed by Airlock: policy rule `{rule}`]"},
        ],
        "isError": False,
    }


__all__ = ["REDACTED_ARGUMENT", "redact_arguments", "withheld_result"]
