"""Per-session taint table with LRU eviction, TTL and Aho-Corasick matching.

Matching uses two automata per key family:

- a *main* automaton holding most keys, rebuilt only when the delta is merged
  into it or when too many evicted keys (tombstones) have accumulated;
- a small *delta* automaton holding keys added since the last merge, rebuilt
  after each batch of additions (cheap because it is small).

Both rebuilds happen on the write path (:meth:`TaintTable.commit`), never while
scanning an outbound call. Evicted or expired keys stay in the automata as
tombstones and are filtered out when they match.
"""

from __future__ import annotations

import re
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Final, Literal

import ahocorasick

from airlock.taint.extract import Kind
from airlock.taint.normalize import Family, compact, normalize_domain, views

TaintLabel = Literal["untrusted", "secret"]

_DELTA_MAX: Final = 1024
# Linear-time host finder: dotted words; the top-level label is checked afterwards.
_HOST_IN_TEXT = re.compile(r"(?<![\w.-])[\w-]++(?:\.[\w-]++)+")
_BOUNDARY_KINDS: Final = frozenset({"url", "email", "path", "phone", "iban", "account", "domain"})


@dataclass
class TaintEntry:
    """A tainted value and where it came from."""

    key: str
    family: Family
    kind: Kind
    value: str
    label: TaintLabel
    source_server: str
    source_tool: str
    call_index: int
    snippet: str
    first_seen: float
    last_seen: float

    @property
    def source(self) -> str:
        return f"{self.source_server}.{self.source_tool}"


@dataclass(frozen=True)
class TaintMatch:
    """A tainted value found in an outbound string."""

    entry: TaintEntry
    how: str  # "exact", "substring", "domain", "url-decoded", "base64", "hex", ...

    @property
    def encoded(self) -> bool:
        return self.how not in {"exact", "substring", "domain"}


@dataclass
class _Automata:
    main: ahocorasick.Automaton = field(default_factory=ahocorasick.Automaton)
    delta: ahocorasick.Automaton = field(default_factory=ahocorasick.Automaton)
    main_size: int = 0
    delta_size: int = 0
    delta_dirty: bool = False

    @staticmethod
    def _ready(automaton: ahocorasick.Automaton) -> bool:
        return bool(automaton.kind == ahocorasick.AHOCORASICK)

    def iter(self, text: str) -> Iterable[tuple[int, str]]:
        for automaton in (self.main, self.delta):
            if self._ready(automaton):
                yield from automaton.iter(text)


class TaintTable:
    """Tainted values for one session."""

    def __init__(
        self,
        max_entries: int = 10_000,
        ttl_seconds: float = 3600.0,
        min_token_length: int = 16,
        match_domains: bool = True,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.max_entries = max_entries
        self.ttl_seconds = ttl_seconds
        self.min_token_length = min_token_length
        self.match_domains = match_domains
        self._clock = clock
        self._entries: OrderedDict[tuple[Family, str], TaintEntry] = OrderedDict()
        self._domains: dict[str, tuple[Family, str]] = {}
        self._automata: dict[Family, _Automata] = {"text": _Automata(), "compact": _Automata()}
        self._tombstones = 0
        self.evictions = 0

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, key: tuple[Family, str]) -> bool:
        return key in self._entries

    def entries(self) -> list[TaintEntry]:
        return list(self._entries.values())

    # ------------------------------------------------------------------ write

    def add(
        self,
        *,
        key: str,
        family: Family,
        kind: Kind,
        value: str,
        label: TaintLabel,
        source_server: str,
        source_tool: str,
        call_index: int,
        snippet: str,
    ) -> TaintEntry:
        """Record a tainted value. Call :meth:`commit` after a batch of additions."""
        now = self._clock()
        table_key = (family, key)
        existing = self._entries.get(table_key)
        if existing is not None:
            self._entries.move_to_end(table_key)
            existing.last_seen = now
            # Secret taint is never downgraded by a later untrusted sighting.
            if label == "secret" or existing.label == "untrusted":
                existing.label = label
                existing.source_server = source_server
                existing.source_tool = source_tool
                existing.call_index = call_index
                existing.snippet = snippet
            return existing

        entry = TaintEntry(
            key=key,
            family=family,
            kind=kind,
            value=value,
            label=label,
            source_server=source_server,
            source_tool=source_tool,
            call_index=call_index,
            snippet=snippet,
            first_seen=now,
            last_seen=now,
        )
        self._entries[table_key] = entry
        if kind == "domain":
            self._domains[key] = table_key
        else:
            automata = self._automata[family]
            if not automata.delta.exists(key) and not automata.main.exists(key):
                automata.delta.add_word(key, key)
                automata.delta_size += 1
                automata.delta_dirty = True
            else:
                # The key is a tombstone from an earlier eviction; it is live again.
                self._tombstones = max(0, self._tombstones - 1)
        while len(self._entries) > self.max_entries:
            self._evict_oldest()
        return entry

    def commit(self) -> None:
        """Rebuild automata after additions; merge the delta into main when it grows large."""
        self._purge_expired()
        for family, automata in self._automata.items():
            if automata.delta_size > _DELTA_MAX:
                self._rebuild_main(family)
            elif automata.delta_dirty:
                automata.delta.make_automaton()
                automata.delta_dirty = False
        if self._tombstones > max(1000, len(self._entries) // 2):
            for family in self._automata:
                self._rebuild_main(family)

    def _rebuild_main(self, family: Family) -> None:
        main = ahocorasick.Automaton()
        count = 0
        for (entry_family, key), entry in self._entries.items():
            if entry_family == family and entry.kind != "domain" and not main.exists(key):
                main.add_word(key, key)
                count += 1
        if count:
            main.make_automaton()
        self._automata[family] = _Automata(main=main, main_size=count)
        self._tombstones = 0

    def _evict_oldest(self) -> None:
        table_key, entry = self._entries.popitem(last=False)
        self._forget(table_key, entry)
        self.evictions += 1

    def _forget(self, table_key: tuple[Family, str], entry: TaintEntry) -> None:
        if entry.kind == "domain":
            self._domains.pop(entry.key, None)
        else:
            self._tombstones += 1

    def _purge_expired(self) -> None:
        if self.ttl_seconds <= 0:
            return
        cutoff = self._clock() - self.ttl_seconds
        while self._entries:
            table_key, entry = next(iter(self._entries.items()))
            if entry.last_seen >= cutoff:
                break
            del self._entries[table_key]
            self._forget(table_key, entry)

    def _live(self, table_key: tuple[Family, str]) -> TaintEntry | None:
        entry = self._entries.get(table_key)
        if entry is None:
            return None
        if self.ttl_seconds > 0 and entry.last_seen < self._clock() - self.ttl_seconds:
            return None
        return entry

    # ------------------------------------------------------------------- read

    def match(self, value: str) -> list[TaintMatch]:
        """Find tainted values in one outbound string (all decoded views, both families)."""
        if not self._entries:
            return []
        found: dict[tuple[Family, str], TaintMatch] = {}
        for view in views(value):
            haystacks: tuple[tuple[Family, str], ...] = (
                ("text", view.text),
                ("compact", compact(view.text)),
            )
            for family, text in haystacks:
                automata = self._automata[family]
                for end, key in automata.iter(text):
                    table_key = (family, key)
                    if table_key in found:
                        continue
                    entry = self._live(table_key)
                    if entry is None:
                        continue
                    start = end - len(key) + 1
                    if not self._accept(entry, text, start, end + 1):
                        continue
                    how = view.how
                    if how == "plain":
                        how = "exact" if start == 0 and end + 1 == len(text) else "substring"
                    found[table_key] = TaintMatch(entry, how)
            # Domain matching is the weakest layer: only used when nothing more
            # specific matched this string, so one value yields one reason.
            if self.match_domains and self._domains and not found and "." in view.text:
                for host in _HOST_IN_TEXT.findall(view.text):
                    tld = host.rsplit(".", 1)[-1]
                    if len(tld) < 2 or not tld.isalpha():
                        continue
                    domain_match = self._match_domain(host)
                    if domain_match is not None and domain_match[0] not in found:
                        how = "domain" if view.how == "plain" else view.how
                        found[domain_match[0]] = TaintMatch(domain_match[1], how)
        # A value that keeps showing up in outbound calls stays tainted: refresh
        # both its LRU position and its TTL clock (keeps the dict in time order).
        now = self._clock()
        for table_key in found:
            self._entries[table_key].last_seen = now
            self._entries.move_to_end(table_key)
        return list(found.values())

    def _accept(self, entry: TaintEntry, text: str, start: int, end: int) -> bool:
        """Short structured values must not be part of a longer word or number."""
        if entry.kind not in _BOUNDARY_KINDS:
            return True
        before = text[start - 1] if start > 0 else ""
        after = text[end] if end < len(text) else ""
        if entry.family == "compact":
            return not before.isdigit() and not after.isdigit()
        return not before.isalnum() and not after.isalnum()

    def _match_domain(self, host: str) -> tuple[tuple[Family, str], TaintEntry] | None:
        domain = normalize_domain(host)
        labels = domain.split(".")
        for index in range(len(labels) - 1):
            candidate = ".".join(labels[index:])
            table_key = self._domains.get(candidate)
            if table_key is not None:
                entry = self._live(table_key)
                if entry is not None:
                    return table_key, entry
        return None


__all__ = ["TaintEntry", "TaintLabel", "TaintMatch", "TaintTable"]
