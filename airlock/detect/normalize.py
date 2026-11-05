"""Normalization and extraction of adversarial text from tool results."""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Final
from urllib.parse import unquote


@dataclass(frozen=True)
class Finding:
    """A normalization or extraction finding."""

    kind: str
    text: str
    start: int | None = None
    end: int | None = None


@dataclass(frozen=True)
class NormalizedText:
    """Normalized text and facts found while producing it."""

    text: str
    findings: tuple[Finding, ...]
    offset_map: tuple[int, ...]

    def original_span(self, start: int, end: int) -> tuple[int, int]:
        """Map a normalized half-open span to the original input span."""
        if not self.offset_map or start >= end:
            return (0, 0)
        start = max(0, min(start, len(self.offset_map) - 1))
        end_index = max(start, min(end - 1, len(self.offset_map) - 1))
        return (self.offset_map[start], self.offset_map[end_index] + 1)


_ZERO_WIDTH: Final = frozenset("\u200b\u200c\u200d\ufeff\u2060")
_BIDI: Final = frozenset("\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
_CONFUSABLES: Final = str.maketrans(
    {
        "\u0430": "a",
        "\u0410": "A",
        "\u0435": "e",
        "\u0415": "E",
        "\u043e": "o",
        "\u041e": "O",
        "\u0440": "p",
        "\u0420": "P",
        "\u0441": "c",
        "\u0421": "C",
        "\u0445": "x",
        "\u0425": "X",
        "\u0443": "y",
        "\u0423": "Y",
        "\u0456": "i",
        "\u0406": "I",
        "\u0458": "j",
        "\u0408": "J",
        "\u03bd": "v",
        "\u039d": "N",
        "\u03bf": "o",
        "\u039f": "O",
        "\u03c1": "p",
        "\u03a1": "P",
        "\u03c4": "t",
        "\u03a4": "T",
        "\u03b9": "i",
        "\u0399": "I",
        "\u03ba": "k",
        "\u039a": "K",
        "\u03bc": "m",
        "\u039c": "M",
    }
)


class _HTMLExtractor(HTMLParser):
    """Collect potentially hidden HTML text and metadata."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.comments: list[str] = []
        self.hidden: list[str] = []
        self.attributes: list[str] = []
        self._hidden_depth = 0

    @staticmethod
    def _is_hidden(attrs: list[tuple[str, str | None]]) -> bool:
        values = {key.lower(): (value or "").lower() for key, value in attrs}
        style = values.get("style", "").replace(" ", "")
        tiny_font = re.search(r"font-size:(?:0(?:px|pt|em|rem)?|[01](?:px|pt|em|rem))", style)
        return (
            "display:none" in style
            or "visibility:hidden" in style
            or values.get("aria-hidden") == "true"
            or bool(tiny_font)
        )

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del tag
        if self._is_hidden(attrs):
            self._hidden_depth += 1
        for key, value in attrs:
            if key.lower() in {"alt", "title"} and value:
                self.attributes.append(html.unescape(value))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if self._hidden_depth:
            self._hidden_depth -= 1

    def handle_endtag(self, tag: str) -> None:
        del tag
        if self._hidden_depth:
            self._hidden_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._hidden_depth and data.strip():
            self.hidden.append(data)

    def handle_comment(self, data: str) -> None:
        if data.strip():
            self.comments.append(data)


def _append_transformed(
    source: str, mapping: list[int], transform: Callable[[str], str]
) -> tuple[str, list[int]]:
    result: list[str] = []
    result_map: list[int] = []
    for index, char in enumerate(source):
        transformed = transform(char)
        result.extend(transformed)
        result_map.extend([mapping[index]] * len(transformed))
    return "".join(result), result_map


def _decode_blob(blob: str, kind: str) -> str | None:
    try:
        if kind == "base64":
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        elif kind == "hex":
            raw = bytes.fromhex(blob)
        else:
            raw = unquote(blob).encode()
        decoded = raw.decode("utf-8")
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return None
    printable = sum(char.isprintable() or char.isspace() for char in decoded)
    return decoded if decoded and printable / len(decoded) >= 0.85 else None


def normalize(text: str) -> NormalizedText:
    """Normalize text, extracting hidden and encoded content for scanning."""
    original = text
    mapping = list(range(len(text)))
    findings: list[Finding] = []
    if any(char in _ZERO_WIDTH for char in text):
        findings.append(Finding("zero_width", "zero-width characters present"))
    if any(char in _BIDI for char in text):
        findings.append(Finding("bidi_control", "bidirectional controls present"))
    text, mapping = _append_transformed(
        text, mapping, lambda char: "" if char in _ZERO_WIDTH or char in _BIDI else char
    )
    text, mapping = _append_transformed(
        text, mapping, lambda char: unicodedata.normalize("NFKC", char)
    )
    text, mapping = _append_transformed(text, mapping, lambda char: char.translate(_CONFUSABLES))

    parser = _HTMLExtractor()
    if "<" in original:
        try:
            parser.feed(original)
        except ValueError:
            pass
    supplements = parser.comments + parser.hidden + parser.attributes
    if parser.comments:
        findings.append(Finding("html_comment", "HTML comments extracted"))
    if parser.hidden:
        findings.append(Finding("hidden_html", "hidden HTML text extracted"))
    if parser.attributes:
        findings.append(Finding("html_attribute", "alt/title attributes extracted"))
    supplement_suffix = "\n" + "\n".join(supplements)
    if supplements and not text.endswith(supplement_suffix):
        text += "\n" + "\n".join(supplements)
        supplement_mapping: list[int] = []
        search_from = 0
        for supplement in supplements:
            position = original.find(supplement, search_from)
            source_position = max(position, 0)
            supplement_mapping.extend(source_position + offset for offset in range(len(supplement)))
            search_from = source_position + len(supplement)
        mapping.extend([0, *supplement_mapping])

    blob_patterns = (
        (
            "base64",
            re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{25,}={0,2}(?![A-Za-z0-9+/])"),
        ),
        ("hex", re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{25,}(?![0-9A-Fa-f])")),
        ("url_encoded", re.compile(r"(?:%[0-9A-Fa-f]{2}){9,}")),
    )
    decoded: list[str] = []
    decoded_mappings: list[int] = []
    for kind, pattern in blob_patterns:
        for match in pattern.finditer(text):
            value = _decode_blob(match.group(), kind)
            if value:
                findings.append(Finding(f"decoded_{kind}", value, match.start(), match.end()))
                decoded.append(value)
                source_start, source_end = NormalizedText(text, (), tuple(mapping)).original_span(
                    match.start(), match.end()
                )
                source_width = max(1, source_end - source_start)
                decoded_mappings.extend(
                    source_start + min(index, source_width - 1) for index in range(len(value))
                )
    decoded_suffix = "\n" + "\n".join(decoded)
    if decoded and not text.endswith(decoded_suffix):
        text += "\n" + "\n".join(decoded)
        suffix_mapping = [0]
        cursor = 0
        for index, value in enumerate(decoded):
            if index:
                suffix_mapping.append(0)
            suffix_mapping.extend(decoded_mappings[cursor : cursor + len(value)])
            cursor += len(value)
        mapping.extend(suffix_mapping)

    if re.search(r"!\[[^\]]*\]\([^)]{0,200}[?&][^)]{24,}\)", text):
        findings.append(Finding("long_markdown_url", "Markdown image URL has a long query string"))
    if re.search(r"(?<!!)\[[^\]]+\]\([^)]{0,200}[?&][^)]{24,}\)", text):
        findings.append(Finding("long_markdown_url", "Markdown link URL has a long query string"))
    return NormalizedText(text, tuple(findings), tuple(mapping))


__all__ = ["Finding", "NormalizedText", "normalize"]
