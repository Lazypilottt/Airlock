"""Canonical forms for tainted values and decoded views of outbound strings.

Every tainted value gets a *match key* in one of two families:

- ``text``: lowercased, URL-decoded, scheme-stripped, punycode decoded. Used for
  URLs, emails, paths, API keys and long tokens.
- ``compact``: lowercased with spaces and punctuation removed. Used for phone,
  IBAN and account numbers, which are written with arbitrary separators.

Outbound argument strings are expanded into *views* (lowercased, URL-decoded,
punycode-decoded, HTML-unescaped, and base64/hex-decoded blobs) and every view
is searched for keys of the matching family.
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass
from typing import Final, Literal
from urllib.parse import unquote, unquote_plus

Family = Literal["text", "compact"]

_ZERO_WIDTH_AND_BIDI: Final = dict.fromkeys(
    map(
        ord,
        "​‌‍﻿⁠­؜‎‏‪‫‬‭‮⁦⁧⁨⁩",
    )
)
_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_XN_LABEL = re.compile(r"(?<![a-z0-9-])xn--[a-z0-9-]+", re.IGNORECASE)
_COMPACT_DROP = re.compile(r"[\s().+/\-_:]")
# Possessive quantifiers and start-of-run lookbehinds keep these scans linear.
_BASE64_BLOB = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}+={0,2}")
_HEX_BLOB = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{16,}+")
_MAX_DECODE_ROUNDS: Final = 3
_MAX_BLOBS: Final = 64


def clean(text: str) -> str:
    """Drop invisible characters and apply NFKC so look-alike forms compare equal."""
    text = text.translate(_ZERO_WIDTH_AND_BIDI)
    return unicodedata.normalize("NFKC", text) if not text.isascii() else text


def decode_punycode_labels(text: str) -> str:
    """Replace ``xn--`` labels with their Unicode form; leave invalid labels alone."""

    def _decode(match: re.Match[str]) -> str:
        label = match.group(0)
        try:
            return label.encode("ascii").decode("idna").lower()
        except (UnicodeError, ValueError):
            return label.lower()

    return _XN_LABEL.sub(_decode, text)


def normalize_domain(host: str) -> str:
    """Lowercase, strip ``www.``, port and trailing dot, and decode punycode."""
    host = clean(host).strip().lower().rstrip(".")
    host = host.split("@")[-1]
    if host.startswith("[") or not host:
        return host
    host = host.split(":", 1)[0]
    host = decode_punycode_labels(host)
    if host.startswith("www."):
        host = host[4:]
    return host


def url_decode(text: str) -> str:
    """URL-decode repeatedly (double encoding is common in exfiltration payloads)."""
    for _ in range(_MAX_DECODE_ROUNDS):
        decoded = unquote_plus(text) if "+" in text and "%" in text else unquote(text)
        if decoded == text:
            break
        text = decoded
    return text


def url_host(url: str) -> str:
    """Return the normalised host of a URL (with or without a scheme)."""
    rest = _SCHEME.sub("", url.strip())
    authority = re.split(r"[/?#]", rest, maxsplit=1)[0]
    return normalize_domain(authority.rsplit("@", 1)[-1])


def url_key(url: str) -> str:
    """Canonical text key for a URL: no scheme, decoded, lowercase host, no trailing slash."""
    value = url_decode(clean(url).strip())
    rest = _SCHEME.sub("", value)
    split = re.split(r"([/?#])", rest, maxsplit=1)
    host = normalize_domain(split[0].rsplit("@", 1)[-1])
    tail = "".join(split[1:]) if len(split) > 1 else ""
    return (host + tail).lower().rstrip("/")


def text_key(value: str) -> str:
    """Canonical text key for emails, paths, API keys and tokens."""
    return decode_punycode_labels(url_decode(clean(value).strip()).lower())


def compact_key(value: str) -> str:
    """Canonical key for numbers written with arbitrary separators."""
    return _COMPACT_DROP.sub("", clean(value).lower())


def compact(text: str) -> str:
    """Compact form of an already lowercased view, for the ``compact`` family."""
    return _COMPACT_DROP.sub("", text)


@dataclass(frozen=True)
class View:
    """One decoded view of an outbound string."""

    how: str  # "plain", "url-decoded", "punycode", "html", "base64", "hex"
    text: str


def _printable(raw: bytes) -> str | None:
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not decoded:
        return None
    printable = sum(char.isprintable() or char.isspace() for char in decoded)
    return decoded if printable / len(decoded) >= 0.9 else None


def _decode_base64(blob: str) -> str | None:
    padded = blob + "=" * (-len(blob) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(padded.encode("ascii"))
        except (binascii.Error, ValueError):
            continue
        text = _printable(raw)
        if text is not None:
            return text
    return None


def _decode_hex(blob: str) -> str | None:
    try:
        return _printable(bytes.fromhex(blob))
    except ValueError:
        return None


def views(value: str) -> list[View]:
    """Return decoded, lowercased views of an outbound string, plain view first."""
    cleaned = clean(value)
    lowered = cleaned.lower()
    result = [View("plain", lowered)]
    seen = {lowered}

    def _add(how: str, text: str) -> None:
        text = text.lower()
        if text not in seen:
            seen.add(text)
            result.append(View(how, text))

    if "%" in cleaned or "+" in cleaned:
        _add("url-decoded", url_decode(cleaned))
    if "xn--" in lowered:
        _add("punycode", decode_punycode_labels(lowered))
    if "&" in cleaned and ";" in cleaned:
        _add("html", html.unescape(cleaned))

    blobs = 0
    for match in _BASE64_BLOB.finditer(cleaned):
        if blobs >= _MAX_BLOBS:
            break
        decoded = _decode_base64(match.group(0).rstrip("="))
        if decoded is not None:
            blobs += 1
            _add("base64", clean(decoded))
    for match in _HEX_BLOB.finditer(cleaned):
        if blobs >= _MAX_BLOBS:
            break
        if len(match.group(0)) % 2:
            continue
        decoded = _decode_hex(match.group(0))
        if decoded is not None:
            blobs += 1
            _add("hex", clean(decoded))
    # A decoded blob may itself be URL-encoded (base64 of a query string, say).
    for view in list(result[1:]):
        if view.how in {"base64", "hex"} and "%" in view.text:
            _add(view.how, url_decode(view.text))
    return result


__all__ = [
    "Family",
    "View",
    "clean",
    "compact",
    "compact_key",
    "decode_punycode_labels",
    "normalize_domain",
    "text_key",
    "url_decode",
    "url_host",
    "url_key",
    "views",
]
