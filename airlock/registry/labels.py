"""Tool labels: which tools read untrusted or secret data and which send data out.

Labels come from three places, highest precedence first:

1. ``labels:`` entries in ``airlock.yaml`` (origin ``user``);
2. label packs in ``packs/labels/*.yaml`` (origin ``pack``);
3. a heuristic over the tool's name, description and input schema (origin ``inferred``).

The first source with an entry for a tool wins outright; sources are not merged.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from airlock.config import LabelOverride
from airlock.models import ToolDef
from airlock.resources import packs_dir


class Label(StrEnum):
    """Data-flow role of a tool."""

    SOURCE_UNTRUSTED = "source_untrusted"
    SOURCE_SECRET = "source_secret"
    SINK = "sink"


class LabelOrigin(StrEnum):
    """Where a tool's labels came from."""

    USER = "user"
    PACK = "pack"
    ACCEPTED = "accepted"  # auto-label reviewed and accepted (`airlock tools review`)
    PROPOSED = "proposed"  # auto-label not reviewed yet: added to the heuristic's labels
    INFERRED = "inferred"
    NONE = "none"


class ArgRole(StrEnum):
    """Role of a tool argument, used by taint and policy checks."""

    DESTINATION = "destination"  # where data goes: recipient, URL, channel, repo
    CONTENT = "content"  # data being sent or written
    PATH = "path"  # a local file path
    CODE = "code"  # code or a shell command that will be executed


class LabelError(Exception):
    """Raised when a label pack or label override is invalid."""


class LabelEntry(BaseModel):
    """One tool entry in a label pack or in ``airlock.yaml``."""

    model_config = ConfigDict(extra="forbid")

    tool: str = Field(min_length=1, description="Tool name or glob (fnmatch syntax).")
    labels: list[Label] = Field(default_factory=list)
    args: dict[str, ArgRole] = Field(default_factory=dict)


class LabelPack(BaseModel):
    """A YAML label pack for one MCP server (or a family of servers)."""

    model_config = ConfigDict(extra="forbid")

    name: str
    description: str = ""
    source: str = ""
    servers: list[str] = Field(min_length=1, description="Globs over server names.")
    tools: list[LabelEntry] = Field(default_factory=list)

    @classmethod
    def load(cls, path: Path | str) -> LabelPack:
        """Load and validate a label pack from YAML."""
        path = Path(path)
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise LabelError(f"Cannot read label pack {path}: {exc}") from exc
        if not isinstance(raw, dict):
            raise LabelError(f"Label pack {path} must be a YAML mapping")
        try:
            return cls.model_validate(raw)
        except ValidationError as exc:
            raise LabelError(f"Invalid label pack {path}: {exc}") from exc

    def matches_server(self, server_id: str) -> bool:
        return any(_glob(server_id, pattern) for pattern in self.servers)


@dataclass(frozen=True)
class ToolLabels:
    """Resolved labels for one tool."""

    labels: frozenset[Label] = frozenset()
    origin: LabelOrigin = LabelOrigin.NONE
    source: str = ""
    arg_roles: Mapping[str, ArgRole] = field(default_factory=dict)
    reasons: tuple[str, ...] = ()

    @property
    def is_sink(self) -> bool:
        return Label.SINK in self.labels

    @property
    def is_source(self) -> bool:
        return Label.SOURCE_UNTRUSTED in self.labels or Label.SOURCE_SECRET in self.labels

    def sorted_labels(self) -> list[str]:
        return sorted(label.value for label in self.labels)

    def to_record(self) -> dict[str, Any]:
        """Serialisable form stored in the registry."""
        return {
            "labels": self.sorted_labels(),
            "origin": self.origin.value,
            "source": self.source,
            "arg_roles": {name: role.value for name, role in sorted(self.arg_roles.items())},
        }

    @classmethod
    def from_record(
        cls,
        labels: Iterable[str],
        origin: str | None,
        source: str | None,
        arg_roles: Mapping[str, str] | None,
    ) -> ToolLabels:
        """Rebuild from registry columns, skipping unknown values."""
        valid = {item.value for item in Label}
        roles = {item.value for item in ArgRole}
        try:
            parsed_origin = LabelOrigin(origin) if origin else LabelOrigin.NONE
        except ValueError:
            parsed_origin = LabelOrigin.NONE
        return cls(
            labels=frozenset(Label(item) for item in labels if item in valid),
            origin=parsed_origin,
            source=source or "",
            arg_roles={
                name: ArgRole(role) for name, role in (arg_roles or {}).items() if role in roles
            },
        )


def _glob(value: str, pattern: str) -> bool:
    return fnmatch.fnmatchcase(value.lower(), pattern.lower())


class _HasTool(Protocol):
    @property
    def tool(self) -> str: ...


def _find_entry[EntryT: _HasTool](entries: Sequence[EntryT], tool_name: str) -> EntryT | None:
    """Return the entry for ``tool_name``: an exact name beats any glob; globs go in file order."""
    for entry in entries:
        if entry.tool == tool_name:
            return entry
    for entry in entries:
        if _glob(tool_name, entry.tool):
            return entry
    return None


# ---------------------------------------------------------------------------
# Heuristic
# ---------------------------------------------------------------------------

# Strong sink verbs mark a tool as a sink wherever they appear in its name
# ("issue_write", "send_email"). Weak ones only count as the leading verb, so
# "get_post" and "list_comments" stay sources.
_STRONG_SINK_VERBS = frozenset(
    {
        "send",
        "write",
        "delete",
        "execute",
        "exec",
        "upload",
        "publish",
        "transfer",
        "pay",
        "payment",
        "shell",
        "push",
        "merge",
        "deploy",
        "kill",
        "webhook",
        "http",
        "curl",
        "wget",
    }
)
_WEAK_SINK_VERBS = frozenset(
    {
        "post",
        "create",
        "update",
        "put",
        "patch",
        "run",
        "remove",
        "move",
        "rename",
        "edit",
        "append",
        "insert",
        "comment",
        "reply",
        "invite",
        "share",
        "install",
        "submit",
        "set",
        "save",
        "store",
        "forward",
        "notify",
        "tweet",
        "drop",
        "add",
        "request",
    }
)
_ALWAYS_UNTRUSTED_VERBS = frozenset(
    {"fetch", "browse", "scrape", "crawl", "navigate", "download", "http", "curl", "wget"}
)
_READ_VERBS = frozenset(
    {"read", "get", "search", "list", "query", "view", "load", "open", "retrieve", "find", "lookup"}
)
_EXTERNAL_NOUNS = frozenset(
    {
        "web",
        "url",
        "uri",
        "page",
        "pages",
        "site",
        "website",
        "webpage",
        "html",
        "http",
        "https",
        "internet",
        "online",
        "external",
        "email",
        "emails",
        "mail",
        "inbox",
        "message",
        "messages",
        "issue",
        "issues",
        "comment",
        "comments",
        "chat",
        "chats",
        "slack",
        "discord",
        "tweet",
        "tweets",
        "post",
        "posts",
        "repo",
        "repos",
        "repository",
        "pull",
        "feed",
        "rss",
        "news",
        "document",
        "documents",
        "ticket",
        "tickets",
        "review",
        "reviews",
        "forum",
        "channel",
        "channels",
        "thread",
        "threads",
        "calendar",
        "event",
        "events",
    }
)
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(pattern, re.IGNORECASE), why)
    for pattern, why in (
        (r"(?:^|[^a-z0-9])\.env\b", "mentions .env files"),
        (r"\benv(?:ironment)?[ _-]?var(?:iable)?s?\b", "mentions environment variables"),
        (r"~/\.ssh|\bssh[ _-]?keys?\b|\bid_rsa\b|\bid_ed25519\b", "mentions SSH keys"),
        (r"\bsecrets?\b", "mentions secrets"),
        (r"\bcredentials?\b", "mentions credentials"),
        (r"\bpasswords?\b|\bpasswd\b", "mentions passwords"),
        (r"\bapi[ _-]?keys?\b|\bapikeys?\b", "mentions API keys"),
        (r"\b(?:access|secret|private|signing)[ _-]?keys?\b", "mentions keys"),
        (r"\b(?:access|auth|bearer|refresh|session|oauth)[ _-]?tokens?\b", "mentions tokens"),
        (r"\bkeychain\b|\bkeyring\b|\bvault\b", "mentions a key store"),
        (r"\bcookies?\b", "mentions cookies"),
    )
)
_SINK_SCHEMA_PROPS = frozenset(
    {
        "to",
        "recipient",
        "recipients",
        "cc",
        "bcc",
        "webhook",
        "webhook_url",
        "command",
        "cmd",
        "script",
        "shell",
    }
)
_DESTINATION_PROPS = frozenset(
    {
        "to",
        "recipient",
        "recipients",
        "cc",
        "bcc",
        "url",
        "uri",
        "endpoint",
        "webhook",
        "webhook_url",
        "channel",
        "channel_id",
        "destination",
        "email",
        "address",
        "host",
        "iban",
        "account",
        "phone",
        "number",
    }
)
_CONTENT_PROPS = frozenset(
    {"body", "content", "text", "message", "payload", "data", "subject", "title"}
)
_CODE_PROPS = frozenset({"command", "cmd", "script", "code", "shell"})
_PATH_PROPS = frozenset({"path", "file", "filename", "filepath", "file_path"})

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_WORD = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> list[str]:
    return _WORD.findall(_CAMEL.sub(" ", text).lower())


def _schema_properties(schema: Mapping[str, Any]) -> list[str]:
    props = schema.get("properties") if isinstance(schema, Mapping) else None
    return [str(name) for name in props] if isinstance(props, Mapping) else []


def infer_labels(tool: ToolDef) -> ToolLabels:
    """Guess labels from a tool's name, description and input schema."""
    name_tokens = _tokens(tool.name)
    description = tool.description or ""
    desc_tokens = set(_tokens(description))
    properties = _schema_properties(tool.input_schema)
    prop_set = {prop.lower() for prop in properties}
    labels: set[Label] = set()
    reasons: list[str] = []

    sink_verbs = [token for token in name_tokens if token in _STRONG_SINK_VERBS]
    if not sink_verbs and name_tokens and name_tokens[0] in _WEAK_SINK_VERBS:
        sink_verbs = [name_tokens[0]]
    if sink_verbs:
        labels.add(Label.SINK)
        reasons.append(f"sink: name contains '{sink_verbs[0]}'")
    elif prop_set & _SINK_SCHEMA_PROPS:
        labels.add(Label.SINK)
        prop = sorted(prop_set & _SINK_SCHEMA_PROPS)[0]
        reasons.append(f"sink: input schema has '{prop}'")

    always = [token for token in name_tokens if token in _ALWAYS_UNTRUSTED_VERBS]
    reads = [token for token in name_tokens if token in _READ_VERBS]
    external = (set(name_tokens) | desc_tokens) & _EXTERNAL_NOUNS
    if always:
        labels.add(Label.SOURCE_UNTRUSTED)
        reasons.append(f"source_untrusted: name contains '{always[0]}'")
    elif reads and external:
        labels.add(Label.SOURCE_UNTRUSTED)
        reasons.append(
            f"source_untrusted: '{reads[0]}' on external content ('{sorted(external)[0]}')"
        )
    elif reads and prop_set & {"url", "uri"}:
        labels.add(Label.SOURCE_UNTRUSTED)
        reasons.append(f"source_untrusted: '{reads[0]}' takes a URL")

    secret_text = " ".join([tool.name, " ".join(name_tokens), description, " ".join(properties)])
    for pattern, why in _SECRET_PATTERNS:
        if pattern.search(secret_text):
            labels.add(Label.SOURCE_SECRET)
            reasons.append(f"source_secret: {why}")
            break

    arg_roles: dict[str, ArgRole] = {}
    if Label.SINK in labels:
        for prop in properties:
            lowered = prop.lower()
            if lowered in _CODE_PROPS:
                arg_roles[prop] = ArgRole.CODE
            elif lowered in _DESTINATION_PROPS:
                arg_roles[prop] = ArgRole.DESTINATION
            elif lowered in _PATH_PROPS:
                arg_roles[prop] = ArgRole.PATH
            elif lowered in _CONTENT_PROPS:
                arg_roles[prop] = ArgRole.CONTENT

    if not labels:
        return ToolLabels(origin=LabelOrigin.NONE, source="heuristic")
    return ToolLabels(
        labels=frozenset(labels),
        origin=LabelOrigin.INFERRED,
        source="heuristic",
        arg_roles=arg_roles,
        reasons=tuple(reasons),
    )


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------


def builtin_label_packs_dir() -> Path:
    return packs_dir() / "labels"


def load_label_packs(directory: Path | str | None = None) -> list[LabelPack]:
    """Load every ``*.yaml`` pack in ``directory`` (default: the bundled packs), sorted by name."""
    root = Path(directory) if directory is not None else builtin_label_packs_dir()
    if not root.is_dir():
        return []
    return [LabelPack.load(path) for path in sorted(root.glob("*.yaml"))]


class ReviewedLabels(Protocol):
    """Lookup of auto-label records (``airlock.registry.autolabel.LabelStore``)."""

    def get(self, tool_hash: str) -> dict[str, Any] | None: ...


class LabelResolver:
    """Resolve a tool's labels: user > pack > auto-label (accepted, or proposed) > heuristic.

    A proposed auto-label is merged with the heuristic (labels can be added,
    never removed); an accepted one is used as reviewed; a rejected one is
    ignored. Proposals below ``min_confidence`` are ignored too.
    """

    def __init__(
        self,
        packs: Sequence[LabelPack] | None = None,
        user_entries: Sequence[LabelOverride] | None = None,
        use_heuristics: bool = True,
    ) -> None:
        self.packs: list[LabelPack] = list(packs) if packs is not None else load_label_packs()
        self.user_entries: list[LabelOverride] = list(user_entries or [])
        self.use_heuristics = use_heuristics
        self.auto_labels: ReviewedLabels | None = None
        self.min_confidence = 0.0

    def has_explicit(self, server_id: str, tool_name: str) -> bool:
        """True when a user entry or a label pack covers the tool."""
        if self._user_entry(server_id, tool_name) is not None:
            return True
        return any(
            pack.matches_server(server_id) and _find_entry(pack.tools, tool_name) is not None
            for pack in self.packs
        )

    def _auto(self, tool: ToolDef, heuristic: ToolLabels) -> ToolLabels | None:
        if self.auto_labels is None:
            return None
        from airlock.registry.store import compute_tool_hash

        record = self.auto_labels.get(compute_tool_hash(tool)[0])
        if record is None or record.get("status") == "rejected":
            return None
        valid_labels = {item.value for item in Label}
        valid_roles = {item.value for item in ArgRole}
        labels = frozenset(Label(x) for x in record.get("labels", []) if x in valid_labels)
        args = {
            str(name): ArgRole(role)
            for name, role in (record.get("args") or {}).items()
            if role in valid_roles
        }
        source = f"{record.get('provider', 'auto')}:{record.get('model', '')}"
        if record.get("status") == "accepted":
            return ToolLabels(
                labels=labels, origin=LabelOrigin.ACCEPTED, source=source, arg_roles=args
            )
        if float(record.get("confidence", 0.0)) < self.min_confidence:
            return None
        return ToolLabels(
            labels=labels | heuristic.labels,
            origin=LabelOrigin.PROPOSED,
            source=source,
            arg_roles={**args, **dict(heuristic.arg_roles)},
            reasons=(str(record.get("rationale", "")),),
        )

    def _user_entry(self, server_id: str, tool_name: str) -> LabelOverride | None:
        candidates = [entry for entry in self.user_entries if _glob(server_id, entry.server)]
        return _find_entry(candidates, tool_name)

    def resolve(self, server_id: str, tool: ToolDef) -> ToolLabels:
        """Return the labels for ``tool`` on ``server_id``."""
        user = self._user_entry(server_id, tool.name)
        if user is not None:
            return ToolLabels(
                labels=frozenset(Label(label) for label in user.labels),
                origin=LabelOrigin.USER,
                source="airlock.yaml",
                arg_roles={name: ArgRole(role) for name, role in user.args.items()},
            )
        for pack in self.packs:
            if not pack.matches_server(server_id):
                continue
            entry = _find_entry(pack.tools, tool.name)
            if entry is not None:
                return ToolLabels(
                    labels=frozenset(entry.labels),
                    origin=LabelOrigin.PACK,
                    source=pack.name,
                    arg_roles=dict(entry.args),
                )
        heuristic = infer_labels(tool) if self.use_heuristics else ToolLabels()
        auto = self._auto(tool, heuristic)
        if auto is not None:
            return auto
        return heuristic


__all__ = [
    "ArgRole",
    "Label",
    "LabelEntry",
    "LabelError",
    "LabelOrigin",
    "LabelPack",
    "LabelResolver",
    "ReviewedLabels",
    "ToolLabels",
    "builtin_label_packs_dir",
    "infer_labels",
    "load_label_packs",
]
