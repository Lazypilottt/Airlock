"""Extract values from tool results that must not later flow into sinks."""

from __future__ import annotations

import functools
import re
from dataclasses import dataclass
from typing import Final, Literal

from airlock.taint.normalize import (
    Family,
    clean,
    compact_key,
    normalize_domain,
    text_key,
    url_host,
    url_key,
)

Kind = Literal["url", "domain", "email", "phone", "path", "iban", "account", "api_key", "token"]

_MIN_KEY_LENGTH: Final = 6
_MAX_VALUES_PER_TEXT: Final = 5000
_MAX_TEXT_CHARS: Final = 1_000_000

_URL = re.compile(r"(?i)\b(?:https?|ftp|wss?)://[^\s<>\"'`]+|\bwww\.[^\s<>\"'`]+")
_EMAIL = re.compile(r"[\w.%+-]+@(?:[\w-]+\.)+[^\W\d_]{2,}")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b")
_NUMBER = re.compile(r"(?<![\w+])\+?\(?\d[\d\s().-]{6,24}\d(?![\w])")
_DATE_LIKE = re.compile(r"^\d{4}-\d{2}-\d{2}$|^\d{2}[./-]\d{2}[./-]\d{4}$")
_UNIX_PATH = re.compile(r"(?<![\w/:.~-])(?:~|\.{1,2})?/(?:[\w.@-]+/)*[\w.@-]+/?")
_WINDOWS_PATH = re.compile(r"\b[A-Za-z]:\\(?:[\w .@-]+\\)*[\w.@-]+")
_KNOWN_KEYS = re.compile(
    r"\b(?:"
    r"AKIA[0-9A-Z]{16}"
    r"|ASIA[0-9A-Z]{16}"
    r"|gh[pousr]_[A-Za-z0-9]{36,}"
    r"|github_pat_[A-Za-z0-9_]{22,}"
    r"|sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}"
    r"|xox[abposr]-[A-Za-z0-9-]{10,}"
    r"|AIza[0-9A-Za-z_-]{35}"
    r"|glpat-[A-Za-z0-9_-]{20,}"
    r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    r")"
)
_KEY_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|access[_-]?key|private[_-]?key)"
    r"\b[\"']?\s*[:=]\s*[\"']?([^\s\"',;]{8,})"
)
_GENERIC_SECRET = re.compile(
    r"(?<![\w-])(?=[A-Za-z0-9_\-]*\d)(?=[A-Za-z0-9_\-]*[A-Za-z])[A-Za-z0-9_\-]{24,}"
)


@functools.lru_cache(maxsize=8)
def _token_pattern(min_length: int) -> re.Pattern[str]:
    return re.compile(rf"\S{{{min_length},}}")


_TRIM = "\"'`.,;:!?)]}>("


@dataclass(frozen=True)
class ExtractedValue:
    """A value found in a tool result, with its canonical match key."""

    kind: Kind
    value: str
    key: str
    family: Family
    start: int
    end: int


def _trim(value: str, start: int) -> tuple[str, int]:
    stripped_left = value.lstrip(_TRIM)
    start += len(value) - len(stripped_left)
    return stripped_left.rstrip(_TRIM), start


def _number_kind(raw: str, digits: str) -> Kind | None:
    if _DATE_LIKE.match(raw.strip()):
        return None
    if not 8 <= len(digits) <= 19:
        return None
    if raw.startswith("+") or "(" in raw or (" " in raw.strip() and len(digits) <= 15):
        return "phone"
    return "account"


def extract_values(
    text: str,
    min_token_length: int = 16,
) -> list[ExtractedValue]:
    """Extract URLs, domains, emails, numbers, paths, keys and long tokens from ``text``."""
    text = clean(text[:_MAX_TEXT_CHARS])
    found: dict[tuple[Family, str], ExtractedValue] = {}
    covered: list[tuple[int, int]] = []

    def _add(kind: Kind, value: str, start: int, family: Family, key: str) -> None:
        if len(found) >= _MAX_VALUES_PER_TEXT or len(key) < _MIN_KEY_LENGTH:
            return
        entry_key = (family, key)
        if entry_key not in found:
            found[entry_key] = ExtractedValue(kind, value, key, family, start, start + len(value))

    def _covered(start: int, end: int) -> bool:
        return any(s <= start and end <= e for s, e in covered)

    for match in _KNOWN_KEYS.finditer(text):
        _add("api_key", match.group(0), match.start(), "text", text_key(match.group(0)))
        covered.append(match.span())
    for match in _KEY_ASSIGNMENT.finditer(text):
        value = match.group(1)
        _add("api_key", value, match.start(1), "text", text_key(value))
        covered.append(match.span(1))

    for match in _URL.finditer(text):
        value, start = _trim(match.group(0), match.start())
        if not value:
            continue
        _add("url", value, start, "text", url_key(value))
        host = url_host(value)
        if "." in host:
            _add("domain", host, start, "text", host)
        covered.append((start, start + len(value)))

    for match in _EMAIL.finditer(text):
        value, start = _trim(match.group(0), match.start())
        local, _, domain = value.rpartition("@")
        if not local or not domain:
            continue
        domain_key = normalize_domain(domain)
        _add("email", value, start, "text", f"{text_key(local)}@{domain_key}")
        _add("domain", domain, start + len(local) + 1, "text", domain_key)
        covered.append((start, start + len(value)))

    for match in _IBAN.finditer(text):
        key = compact_key(match.group(0))
        if 15 <= len(key) <= 34:
            _add("iban", match.group(0), match.start(), "compact", key)
            covered.append(match.span())

    for match in _NUMBER.finditer(text):
        if _covered(*match.span()):
            continue
        raw = match.group(0)
        digits = re.sub(r"\D", "", raw)
        kind = _number_kind(raw, digits)
        if kind is not None:
            _add(kind, raw.strip(), match.start(), "compact", digits)

    for pattern in (_UNIX_PATH, _WINDOWS_PATH):
        for match in pattern.finditer(text):
            if _covered(*match.span()):
                continue
            value, start = _trim(match.group(0), match.start())
            segments = [part for part in re.split(r"[/\\]", value) if part]
            if value.startswith("~") or len(segments) >= 2 or pattern is _WINDOWS_PATH:
                _add("path", value, start, "text", text_key(value))

    for match in _GENERIC_SECRET.finditer(text):
        if _covered(*match.span()):
            continue
        value = match.group(0)
        if len(set(value)) >= 10:
            _add("api_key", value, match.start(), "text", text_key(value))

    for match in _token_pattern(min_token_length).finditer(text):
        value, start = _trim(match.group(0), match.start())
        if len(value) < min_token_length or len(set(value)) < 6:
            continue
        if _covered(start, start + len(value)):
            continue
        _add("token", value, start, "text", text_key(value))

    return list(found.values())


__all__ = ["ExtractedValue", "Kind", "extract_values"]
