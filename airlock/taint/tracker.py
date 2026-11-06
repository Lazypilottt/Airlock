"""Engine checks that record tainted values from results and stop them at sinks."""

from __future__ import annotations

import json
import re
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

from airlock.audit.secrets import mask_secrets
from airlock.config import AirlockConfig
from airlock.detect.normalize import normalize
from airlock.models import Decision, ToolCall, ToolResult, Verdict
from airlock.registry.labels import ArgRole, Label, ToolLabels
from airlock.taint.extract import ExtractedValue, extract_values
from airlock.taint.normalize import Family, compact_key, normalize_domain, text_key
from airlock.taint.table import TaintEntry, TaintLabel, TaintMatch, TaintTable

if TYPE_CHECKING:
    from airlock.engine import Session

LabelLookup = Callable[[str, str], ToolLabels]

_SKIP_RESULT_KEYS: Final = frozenset({"data", "blob", "mimeType", "type", "annotations", "_meta"})
_MAX_STRINGS: Final = 10_000
_SNIPPET_RADIUS: Final = 30
_MAX_TAINTED_CALLS: Final = 1000
_MAX_DERIVED_IDS: Final = 5000
# `id: 26`, `"file_id": "26"`, `eventId=abc-1`: identifiers in a tool result.
_ID_FIELD = re.compile(r"""(?im)["']?\b(id|\w+_id|\w+Id)["']?\s*[:=]\s*["']?([\w.@:/-]{1,64})""")
_STATE_TAINTED_CALLS = "taint.tainted_calls"
_STATE_DERIVED_IDS = "taint.derived_ids"


def _stronger(first: TaintLabel | None, second: TaintLabel | None) -> TaintLabel | None:
    if "secret" in (first, second):
        return "secret"
    return first or second


def _tainted_calls(session: Session) -> OrderedDict[tuple[str, str], TaintLabel]:
    calls: OrderedDict[tuple[str, str], TaintLabel] = session.state.setdefault(
        _STATE_TAINTED_CALLS, OrderedDict()
    )
    return calls


def _derived_ids(session: Session) -> OrderedDict[str, TaintEntry]:
    ids: OrderedDict[str, TaintEntry] = session.state.setdefault(_STATE_DERIVED_IDS, OrderedDict())
    return ids


def _result_ids(strings: list[str], structured: Any) -> set[str]:
    """Identifiers in a result: ``id``/``*_id`` fields, in text or structured content."""
    found: set[str] = set()
    for text in strings:
        found.update(match.group(2) for match in _ID_FIELD.finditer(text))

    def walk(value: Any) -> None:
        if isinstance(value, Mapping):
            for key, item in value.items():
                name = str(key)
                if (
                    (name == "id" or name.endswith(("_id", "Id")))
                    and isinstance(item, (str, int))
                    and not isinstance(item, bool)
                ):
                    found.add(str(item))
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(structured)
    for text in strings:
        try:
            walk(json.loads(text))
        except (ValueError, TypeError):
            pass
    return {value.strip() for value in found if value.strip()}


@dataclass(frozen=True)
class TaintHit:
    """A tainted value found in one argument of an outbound call."""

    arg_path: str
    arg_role: ArgRole | None
    match: TaintMatch

    @property
    def label(self) -> TaintLabel:
        return self.match.entry.label

    @property
    def entry(self) -> TaintEntry:
        return self.match.entry


class TrustedValues:
    """Values that are never treated as tainted (config ``trusted_values``, user prompts)."""

    def __init__(self, values: Iterable[str] = ()) -> None:
        self.keys: set[tuple[Family, str]] = set()
        self.domains: set[str] = set()
        for value in values:
            self.add(value)

    def add(self, value: str) -> None:
        value = value.strip()
        if not value:
            return
        self.keys.add(("text", text_key(value)))
        self.keys.add(("compact", compact_key(value)))
        for extracted in extract_values(value, min_token_length=8):
            self.keys.add((extracted.family, extracted.key))
            # A trusted URL trusts its host; a trusted email trusts only itself.
            if extracted.kind == "domain" and "@" not in value:
                self.domains.add(extracted.key)
        if " " not in value and "." in value and "@" not in value and "/" not in value:
            self.domains.add(normalize_domain(value))

    def __bool__(self) -> bool:
        return bool(self.keys or self.domains)

    def covers(self, family: Family, key: str, kind: str) -> bool:
        if (family, key) in self.keys:
            return True
        if not self.domains or kind not in {"url", "email", "domain"}:
            return False
        host = key.rsplit("@", 1)[-1] if kind == "email" else key.split("/", 1)[0]
        host = host.split("?", 1)[0]
        labels = host.split(".")
        return any(".".join(labels[i:]) in self.domains for i in range(len(labels) - 1))


def _walk_result_strings(value: Any, output: list[str]) -> None:
    if len(output) >= _MAX_STRINGS:
        return
    if isinstance(value, str):
        output.append(value)
    elif isinstance(value, Mapping):
        for key, item in value.items():
            if key not in _SKIP_RESULT_KEYS:
                _walk_result_strings(item, output)
    elif isinstance(value, list):
        for item in value:
            _walk_result_strings(item, output)


def walk_arguments(value: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """Yield ``(path, string)`` for every string in nested arguments, including keys."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            child = f"{path}.{key}" if path else str(key)
            if isinstance(key, str) and len(key) >= 6:
                yield child, key
            yield from walk_arguments(item, child)
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            yield from walk_arguments(item, f"{path}[{index}]")


def _snippet(text: str, value: ExtractedValue) -> str:
    start = max(0, value.start - _SNIPPET_RADIUS)
    end = min(len(text), value.end + _SNIPPET_RADIUS)
    return " ".join(text[start:end].split())


def display_value(entry: TaintEntry) -> str:
    """How a tainted value appears in reasons and logs (secrets are never shown)."""
    if entry.label == "secret":
        head = entry.value[:4]
        return f"{head}… ({len(entry.value)} chars, secret)"
    shown = mask_secrets(entry.value)
    return shown if len(shown) <= 80 else shown[:77] + "..."


def _calls_ago(current: int, then: int) -> str:
    distance = max(0, current - then)
    if distance == 0:
        return "in this call"
    return f"{distance} call{'s' if distance != 1 else ''} ago"


def _root_arg(path: str) -> str:
    for separator in (".", "["):
        path = path.split(separator, 1)[0]
    return path


class TaintRecordCheck:
    """Result check: record values from ``source_untrusted`` / ``source_secret`` results."""

    name = "taint_record"

    def __init__(self, config: AirlockConfig, labels_for: LabelLookup) -> None:
        self.config = config
        self.labels_for = labels_for
        self.trusted = TrustedValues(config.trusted_values)

    async def check(self, result: ToolResult, session: Session) -> Decision:
        labels = self.labels_for(result.server_id, result.tool_name)
        source: TaintLabel | None = None
        if labels.is_source:
            source = "secret" if Label.SOURCE_SECRET in labels.labels else "untrusted"
        # A call that carried tainted data taints what it returns (a file it
        # wrote, an id for it): the data can leave later by reference.
        derived = _tainted_calls(session).pop((result.server_id, str(result.request_id)), None)
        label = _stronger(source, derived)
        if label is None:
            return Decision(verdict=Verdict.ALLOW)
        strings: list[str] = []
        _walk_result_strings(result.content, strings)
        if result.structured_content is not None:
            _walk_result_strings(result.structured_content, strings)

        table = session.taint
        recorded = 0
        for raw in strings:
            text = normalize(raw).text
            for value in extract_values(text, self.config.taint.min_token_length):
                if self.trusted.covers(value.family, value.key, value.kind):
                    continue
                if session.trusted.covers(value.family, value.key, value.kind):
                    continue
                snippet = _snippet(text, value)
                table.add(
                    key=value.key,
                    family=value.family,
                    kind=value.kind,
                    value=value.value,
                    label=label,
                    source_server=result.server_id,
                    source_tool=result.tool_name,
                    call_index=session.call_count,
                    snippet=mask_secrets(snippet) if label == "untrusted" else "",
                )
                recorded += 1
                self._add_compact(table, value, label, result, session)
        table.commit()
        if derived is not None:
            recorded += self._record_ids(strings, result, label, session)
        return Decision(verdict=Verdict.ALLOW, scores={"taint.recorded": float(recorded)})

    def _add_compact(
        self,
        table: TaintTable,
        value: ExtractedValue,
        label: TaintLabel,
        result: ToolResult,
        session: Session,
    ) -> None:
        """Also key long tokens without separators, so `sk-live 9fQ2...` still matches."""
        if value.kind not in {"token", "api_key"}:
            return
        key = compact_key(value.value)
        if len(key) < self.config.taint.min_token_length:
            return
        table.add(
            key=key,
            family="compact",
            kind=value.kind,
            value=value.value,
            label=label,
            source_server=result.server_id,
            source_tool=result.tool_name,
            call_index=session.call_count,
            snippet="",
        )

    def _record_ids(
        self, strings: list[str], result: ToolResult, label: TaintLabel, session: Session
    ) -> int:
        ids = _derived_ids(session)
        now = time.time()
        for value in _result_ids(strings, result.structured_content):
            ids.pop(value, None)
            ids[value] = TaintEntry(
                key=value,
                family="text",
                kind="token",
                value=value,
                label=label,
                source_server=result.server_id,
                source_tool=result.tool_name,
                call_index=session.call_count,
                snippet="",
                first_seen=now,
                last_seen=now,
            )
        while len(ids) > _MAX_DERIVED_IDS:
            ids.popitem(last=False)
        return len(ids)


class TaintCheck:
    """Call check: find tainted values in a call's arguments.

    Every call is scanned and its hits go into ``Decision.evidence["taint"]``
    for the policy, which decides the verdict. On an engine without a policy,
    the check decides itself for tools labelled ``sink``: ASK for untrusted
    taint, DENY for secret taint.
    """

    name = "taint"

    def __init__(self, config: AirlockConfig, labels_for: LabelLookup) -> None:
        self.config = config
        self.labels_for = labels_for
        self.trusted = TrustedValues(config.trusted_values)

    def scan(self, call: ToolCall, session: Session) -> list[TaintHit]:
        """Return taint hits in a call's arguments, ignoring trusted values.

        Each argument string is scanned on its own, then all of them joined
        (path ``*``), so a value split across two arguments is still found.
        An argument that is exactly an id returned for tainted data is a hit too.
        """
        labels = self.labels_for(call.server_id, call.tool_name)
        table = session.taint
        derived = session.state.get(_STATE_DERIVED_IDS)
        if not len(table) and not derived:
            return []
        hits: list[TaintHit] = []
        seen: set[tuple[str, str]] = set()
        found_values: set[str] = set()
        strings = list(walk_arguments(call.arguments))

        def consider(path: str, match: TaintMatch) -> None:
            entry = match.entry
            if self.trusted.covers(entry.family, entry.key, entry.kind):
                return
            if session.trusted.covers(entry.family, entry.key, entry.kind):
                return
            marker = (path, entry.value.lower())
            if marker in seen:
                return
            seen.add(marker)
            found_values.add(entry.value.lower())
            hits.append(TaintHit(path, labels.arg_roles.get(_root_arg(path)), match))

        if len(table):
            for path, value in strings:
                for match in table.match(value):
                    consider(path, match)
            if len(strings) > 1:
                # Only long secrets are worth reassembling: joined text runs words
                # together, so short structured values (emails, domains) would
                # match by accident.
                joined = "".join(value for _, value in strings)
                for match in table.match(joined):
                    entry = match.entry
                    if (
                        entry.kind in {"token", "api_key"}
                        and entry.value.lower() not in found_values
                    ):
                        consider("*", TaintMatch(entry, "split across arguments"))
        if derived:
            for path, value in strings:
                entry = derived.get(value.strip())
                if entry is not None:
                    consider(path, TaintMatch(entry, "derived"))
        return hits

    def reason(self, hit: TaintHit, session: Session) -> str:
        entry = hit.entry
        encoded = f" ({hit.match.how})" if hit.match.encoded else ""
        if hit.match.how == "domain":
            encoded = " (same domain)"
        if hit.match.how == "derived":
            return (
                f"argument `{hit.arg_path}` is {entry.value!r}, an id returned by "
                f"{entry.source} for a call that carried {entry.label} data "
                f"{_calls_ago(session.call_count, entry.call_index)}"
            )
        return (
            f"argument `{hit.arg_path}` contains {display_value(entry)}{encoded}, "
            f"which came from {entry.source} {_calls_ago(session.call_count, entry.call_index)}"
        )

    async def check(self, call: ToolCall, session: Session) -> Decision:
        labels = self.labels_for(call.server_id, call.tool_name)
        hits = sorted(self.scan(call, session), key=lambda hit: hit.label != "secret")
        if hits:
            calls = _tainted_calls(session)
            calls[(call.server_id, str(call.request_id))] = hits[0].label
            while len(calls) > _MAX_TAINTED_CALLS:
                calls.popitem(last=False)
        evidence = {
            "taint": [
                {"path": hit.arg_path, "label": hit.label, "reason": self.reason(hit, session)}
                for hit in hits
            ]
        }
        scores = {"taint.hits": float(len(hits))}
        if not labels.is_sink or not hits:
            return Decision(verdict=Verdict.ALLOW, scores=scores, evidence=evidence)
        secret = hits[0].label == "secret"
        return Decision(
            verdict=Verdict.DENY if secret else Verdict.ASK,
            rule="taint:secret" if secret else "taint:untrusted",
            reasons=[item["reason"] for item in evidence["taint"][:5]],
            scores=scores,
            evidence=evidence,
        )


__all__ = [
    "TaintCheck",
    "TaintHit",
    "TaintRecordCheck",
    "TrustedValues",
    "display_value",
    "walk_arguments",
]
