"""Wrap (``airlock init``) and unwrap (``airlock uninstall``) servers in MCP client configs.

Config locations come from each app's documentation:

- Claude Desktop (modelcontextprotocol.io, "Connect to local MCP servers"):
  macOS ``~/Library/Application Support/Claude/claude_desktop_config.json``,
  Windows ``%APPDATA%\\Claude\\claude_desktop_config.json``,
  Linux ``~/.config/Claude/claude_desktop_config.json``.
- Cursor (cursor.com/docs/context/mcp): ``~/.cursor/mcp.json`` for every
  project (the home directory on every OS), ``.cursor/mcp.json`` per project
  (pass it with ``--config-path``).

Both use ``{"mcpServers": {name: {command, args, env} | {url, headers}}}``.
"""

from __future__ import annotations

import copy
import json
import os
import shutil
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

AppName = Literal["claude-desktop", "cursor"]
APPS: tuple[AppName, ...] = ("claude-desktop", "cursor")
BACKUP_MARKER = ".airlock-backup-"


class InstallError(Exception):
    """Raised when a client config cannot be read, understood or written."""


def config_paths(
    app: AppName,
    platform: str | None = None,
    home: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> list[Path]:
    """Documented MCP config file locations for ``app`` on ``platform``."""
    platform = platform or sys.platform
    home = home or Path.home()
    env = os.environ if env is None else env
    if app == "cursor":
        return [home / ".cursor" / "mcp.json"]
    if platform == "darwin":
        return [home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"]
    if platform == "win32":
        appdata = env.get("APPDATA")
        base = Path(appdata) if appdata else home / "AppData" / "Roaming"
        return [base / "Claude" / "claude_desktop_config.json"]
    return [home / ".config" / "Claude" / "claude_desktop_config.json"]


def default_airlock_command() -> str:
    """The ``airlock`` executable to put in configs.

    Desktop apps start servers with a minimal ``PATH``, so an absolute path
    (next to the running Python, which is where the entry point lives) is
    preferred over the bare name.
    """
    for name in ("airlock", "airlock.exe"):
        beside = Path(sys.executable).parent / name
        if beside.is_file():
            return str(beside)
    found = shutil.which("airlock")
    return found or "airlock"


ServerStatus = Literal["wrap", "wrapped", "remote", "proxied", "invalid"]

FIRST_PROXY_PORT = 8765


@dataclass(frozen=True)
class RemoteEntry:
    """A remote server that a client reaches through a local `airlock serve` port."""

    config: str
    name: str
    upstream: str
    port: int

    @property
    def local_url(self) -> str:
        path = urlsplit(self.upstream).path or "/"
        return f"http://127.0.0.1:{self.port}{path}"


def remote_map_path(data_dir: Path) -> Path:
    return data_dir / "remote-servers.json"


def load_remote_map(data_dir: Path) -> list[RemoteEntry]:
    path = remote_map_path(data_dir)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as exc:
        raise InstallError(f"Cannot read {path}: {exc}") from exc
    entries = raw.get("servers", []) if isinstance(raw, dict) else []
    try:
        return [
            RemoteEntry(str(e["config"]), str(e["name"]), str(e["upstream"]), int(e["port"]))
            for e in entries
        ]
    except (KeyError, TypeError, ValueError) as exc:
        raise InstallError(f"{path} has a malformed entry: {exc}") from exc


def save_remote_map(data_dir: Path, entries: list[RemoteEntry]) -> None:
    path = remote_map_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"servers": [asdict(entry) for entry in entries]}
    write_atomic(path, (json.dumps(payload, indent=2) + "\n").encode("utf-8"))


def _proxied_entry(
    path: Path, name: str, entry: Mapping[str, Any], remote_map: list[RemoteEntry]
) -> RemoteEntry | None:
    url = entry.get("url")
    if not isinstance(url, str):
        return None
    parts = urlsplit(url)
    if parts.hostname not in {"127.0.0.1", "localhost"}:
        return None
    for known in remote_map:
        if known.config == str(path) and known.name == name and known.port == parts.port:
            return known
    return None


@dataclass
class ServerPlan:
    name: str
    status: ServerStatus
    note: str = ""


@dataclass
class ConfigPlan:
    path: Path
    original: bytes
    data: dict[str, Any]
    servers: list[ServerPlan] = field(default_factory=list)

    @property
    def to_wrap(self) -> list[ServerPlan]:
        return [server for server in self.servers if server.status == "wrap"]

    @property
    def wrapped(self) -> list[ServerPlan]:
        return [server for server in self.servers if server.status == "wrapped"]

    @property
    def remote(self) -> list[ServerPlan]:
        return [server for server in self.servers if server.status == "remote"]

    @property
    def proxied(self) -> list[ServerPlan]:
        return [server for server in self.servers if server.status == "proxied"]


def read_config(path: Path) -> tuple[bytes, dict[str, Any]]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise InstallError(f"Cannot read {path}: {exc}") from exc
    if not raw.strip():
        return raw, {}
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstallError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise InstallError(f"{path} must contain a JSON object")
    servers = data.get("mcpServers", {})
    if not isinstance(servers, dict):
        raise InstallError(f"{path}: mcpServers must be an object")
    return raw, data


def _is_remote(entry: Mapping[str, Any]) -> bool:
    kind = str(entry.get("type", "")).lower()
    return "url" in entry or kind in {"http", "sse", "streamable-http", "streamablehttp"}


def is_wrapped(entry: Mapping[str, Any]) -> bool:
    """True if the entry already runs through ``airlock wrap`` (any launcher)."""
    command = entry.get("command")
    args = entry.get("args") or []
    if not isinstance(command, str) or not isinstance(args, list):
        return False
    words = [Path(command).name.lower(), *(str(arg).lower() for arg in args)]
    before_separator = words[: words.index("--")] if "--" in words else words
    for index, word in enumerate(before_separator[:-1]):
        stem = word.removesuffix(".exe")
        if stem in {"airlock", "airlock.cli"} and before_separator[index + 1] == "wrap":
            return True
    return False


def plan(path: Path, remote_map: list[RemoteEntry] | None = None) -> ConfigPlan:
    """What ``init`` would do to one config file."""
    original, data = read_config(path)
    result = ConfigPlan(path=path, original=original, data=data)
    for name, entry in (data.get("mcpServers") or {}).items():
        if not isinstance(entry, dict):
            result.servers.append(ServerPlan(name, "invalid", "entry is not an object"))
        elif (known := _proxied_entry(path, name, entry, remote_map or [])) is not None:
            note = f"already routed through `airlock serve` (port {known.port})"
            result.servers.append(ServerPlan(name, "proxied", note))
        elif _is_remote(entry):
            if isinstance(entry.get("url"), str):
                note = "remote HTTP server; can be routed through `airlock serve`"
            else:
                note = "remote server without a url"
            result.servers.append(ServerPlan(name, "remote", note))
        elif is_wrapped(entry):
            result.servers.append(ServerPlan(name, "wrapped", "already wrapped"))
        elif not isinstance(entry.get("command"), str) or not entry["command"].strip():
            result.servers.append(ServerPlan(name, "invalid", "no command"))
        elif not isinstance(entry.get("args", []), list):
            result.servers.append(ServerPlan(name, "invalid", "args is not a list"))
        else:
            result.servers.append(ServerPlan(name, "wrap"))
    return result


def wrap_entry(
    name: str, entry: dict[str, Any], airlock_command: str, mode: str | None = None
) -> dict[str, Any]:
    """The entry rewritten to run through ``airlock wrap``; every other key is kept."""
    wrapped = copy.deepcopy(entry)
    args = ["wrap", "--name", name]
    if mode is not None:
        args += ["--mode", mode]
    args += ["--", str(entry["command"]), *(str(arg) for arg in entry.get("args", []))]
    wrapped["command"] = airlock_command
    wrapped["args"] = args
    return wrapped


def unwrap_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Undo :func:`wrap_entry`: the command and args after ``--``."""
    args = [str(arg) for arg in entry.get("args", [])]
    if "--" not in args or args.index("--") == len(args) - 1:
        raise InstallError("wrapped entry has no command after `--`")
    original = args[args.index("--") + 1 :]
    unwrapped = copy.deepcopy(entry)
    unwrapped["command"] = original[0]
    unwrapped["args"] = original[1:]
    return unwrapped


def _dump(data: dict[str, Any], original: bytes) -> bytes:
    text = json.dumps(data, indent=2, ensure_ascii=False)
    newline = "\r\n" if b"\r\n" in original else "\n"
    return (text.replace("\n", newline) + newline).encode("utf-8")


def write_atomic(path: Path, content: bytes) -> None:
    """Replace ``path`` atomically, keeping its permissions."""
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def backup(path: Path, original: bytes, now: datetime | None = None) -> Path:
    """Write ``<file>.airlock-backup-<UTC timestamp>`` next to the config, byte for byte."""
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%S%fZ")
    target = path.with_name(f"{path.name}{BACKUP_MARKER}{stamp}")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(original)
    return target


def latest_backup(path: Path) -> Path | None:
    backups = sorted(path.parent.glob(f"{path.name}{BACKUP_MARKER}*"))
    return backups[-1] if backups else None


def proxy_remote(
    config: ConfigPlan, data: dict[str, Any], remote_map: list[RemoteEntry]
) -> list[RemoteEntry]:
    """Point each remote server in ``data`` at a new local port; returns the new map entries."""
    used = {entry.port for entry in remote_map}
    added: list[RemoteEntry] = []
    port = FIRST_PROXY_PORT
    for server in config.remote:
        entry = data["mcpServers"][server.name]
        if not isinstance(entry.get("url"), str):
            continue
        while port in used:
            port += 1
        used.add(port)
        remote = RemoteEntry(str(config.path), server.name, entry["url"], port)
        entry["url"] = remote.local_url
        added.append(remote)
    return added


def apply_init(
    config: ConfigPlan,
    airlock_command: str,
    mode: str | None = None,
    *,
    remote_map: list[RemoteEntry] | None = None,
) -> tuple[Path | None, list[RemoteEntry]]:
    """Back up, then wrap stdio servers (and, with ``remote_map``, route remote ones).

    Returns the backup path (``None`` when nothing changed) and the remote
    servers added to the map; the caller saves the map.
    """
    routing = remote_map is not None and bool(
        [s for s in config.remote if isinstance(config.data["mcpServers"][s.name].get("url"), str)]
    )
    if not config.to_wrap and not routing:
        return None, []
    data = copy.deepcopy(config.data)
    servers = data["mcpServers"]
    for server in config.to_wrap:
        servers[server.name] = wrap_entry(server.name, servers[server.name], airlock_command, mode)
    added = proxy_remote(config, data, remote_map) if remote_map is not None else []
    saved = backup(config.path, config.original)
    write_atomic(config.path, _dump(data, config.original))
    return saved, added


def apply_unwrap_in_place(
    config: ConfigPlan, remote_map: list[RemoteEntry] | None = None
) -> list[str]:
    """Unwrap every wrapped server and un-route proxied ones, without a backup.

    Returns the names changed.
    """
    if not config.wrapped and not config.proxied:
        return []
    data = copy.deepcopy(config.data)
    servers = data["mcpServers"]
    for server in config.wrapped:
        servers[server.name] = unwrap_entry(servers[server.name])
    for server in config.proxied:
        known = _proxied_entry(config.path, server.name, servers[server.name], remote_map or [])
        if known is not None:
            servers[server.name]["url"] = known.upstream
    write_atomic(config.path, _dump(data, config.original))
    return [server.name for server in config.wrapped + config.proxied]


def restore(path: Path, saved: Path) -> None:
    """Put a backup back, byte for byte."""
    write_atomic(path, saved.read_bytes())


STARTER_CONFIG = """\
# Airlock configuration. Every setting is optional; these are the defaults.
# Docs: README.md in the Airlock repository.

# enforce: block, redact and ask. shadow: let everything through, log what
# would have happened (`airlock report` shows it).
mode: enforce

# What happens when a check errors or times out: closed (deny) or open (allow).
fail_mode: closed

# Where the audit log, tool registry and honeytokens live.
# data_dir: ~/.config/airlock

# Policy file. Unset means the default policy bundled with Airlock, which then
# stays current when you upgrade. To customise, copy the bundled file
#   {default_policy}
# edit the copy, and point this at it (it reloads when the file changes).
# `airlock policy check <file>` explains each rule.
# policy: ~/.config/airlock/policy.yaml

# Values that are never treated as tainted (your own addresses and domains).
# trusted_values: [me@example.com, mycompany.example]

# Detector thresholds for tool results (0 to 1).
# redact_above: 0.5
# block_above: 0.85

# Human approvals for `ask` verdicts, on the terminal running the client.
# approvals:
#   terminal: true
#   timeout_seconds: 30
"""


def starter_config_path(home: Path | None = None) -> Path:
    return (home or Path.home()) / ".config" / "airlock" / "airlock.yaml"


def write_starter_config(path: Path) -> bool:
    """Create the starter config; ``False`` (untouched) if anything exists there."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    from airlock.policy.loader import default_policy_path

    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(STARTER_CONFIG.format(default_policy=default_policy_path()))
    return True


__all__ = [
    "APPS",
    "BACKUP_MARKER",
    "FIRST_PROXY_PORT",
    "STARTER_CONFIG",
    "AppName",
    "ConfigPlan",
    "InstallError",
    "RemoteEntry",
    "ServerPlan",
    "apply_init",
    "apply_unwrap_in_place",
    "backup",
    "config_paths",
    "default_airlock_command",
    "is_wrapped",
    "latest_backup",
    "load_remote_map",
    "plan",
    "proxy_remote",
    "read_config",
    "remote_map_path",
    "restore",
    "save_remote_map",
    "starter_config_path",
    "unwrap_entry",
    "wrap_entry",
    "write_atomic",
    "write_starter_config",
]
