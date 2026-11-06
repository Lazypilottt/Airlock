"""Engine checks that record tainted values from results and stop them at sinks."""

from __future__ import annotations

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
from airlock.taint.table import TaintEntry, TaintLabel, TaintMatch

if TYPE_CHECKING:
    from airlock.engine import Session

LabelLookup = Callable[[str, str], ToolLabels]

_SKIP_RESULT_KEYS: Final = frozenset({"data", "blob", "mimeType", "type", "annotations", "_meta"})
_MAX_STRINGS: Final = 10_000
_SNIPPET_RADIUS: Final = 30


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
        if not labels.is_source:
            return Decision(verdict=Verdict.ALLOW)
        label: TaintLabel = "secret" if Label.SOURCE_SECRET in labels.labels else "untrusted"
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
        table.commit()
        return Decision(verdict=Verdict.ALLOW, scores={"taint.recorded": float(recorded)})


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
        """Return taint hits in a call's arguments, ignoring trusted values."""
        labels = self.labels_for(call.server_id, call.tool_name)
        table = session.taint
        if not len(table):
            return []
        hits: list[TaintHit] = []
        seen: set[tuple[str, Family, str]] = set()
        for path, value in walk_arguments(call.arguments):
            for match in table.match(value):
                entry = match.entry
                if self.trusted.covers(entry.family, entry.key, entry.kind):
                    continue
                if session.trusted.covers(entry.family, entry.key, entry.kind):
                    continue
                marker = (path, entry.family, entry.key)
                if marker in seen:
                    continue
                seen.add(marker)
                role = labels.arg_roles.get(_root_arg(path))
                hits.append(TaintHit(path, role, match))
        return hits

    def reason(self, hit: TaintHit, session: Session) -> str:
        entry = hit.entry
        encoded = f" ({hit.match.how})" if hit.match.encoded else ""
        if hit.match.how == "domain":
            encoded = " (same domain)"
        return (
            f"argument `{hit.arg_path}` contains {display_value(entry)}{encoded}, "
            f"which came from {entry.source} {_calls_ago(session.call_count, entry.call_index)}"
        )

    async def check(self, call: ToolCall, session: Session) -> Decision:
        labels = self.labels_for(call.server_id, call.tool_name)
        hits = sorted(self.scan(call, session), key=lambda hit: hit.label != "secret")
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
