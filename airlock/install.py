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
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

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


ServerStatus = Literal["wrap", "wrapped", "remote", "invalid"]


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


def plan(path: Path) -> ConfigPlan:
    """What ``init`` would do to one config file."""
    original, data = read_config(path)
    result = ConfigPlan(path=path, original=original, data=data)
    for name, entry in (data.get("mcpServers") or {}).items():
        if not isinstance(entry, dict):
            result.servers.append(ServerPlan(name, "invalid", "entry is not an object"))
        elif _is_remote(entry):
            note = "remote HTTP server; wrap it with `airlock serve` (coming in the HTTP transport)"
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


def apply_init(config: ConfigPlan, airlock_command: str, mode: str | None = None) -> Path | None:
    """Back up, then wrap every server planned as ``wrap``. Returns the backup path."""
    if not config.to_wrap:
        return None
    data = copy.deepcopy(config.data)
    servers = data["mcpServers"]
    for server in config.to_wrap:
        servers[server.name] = wrap_entry(server.name, servers[server.name], airlock_command, mode)
    saved = backup(config.path, config.original)
    write_atomic(config.path, _dump(data, config.original))
    return saved


def apply_unwrap_in_place(config: ConfigPlan) -> list[str]:
    """Unwrap every wrapped server without a backup. Returns the names unwrapped."""
    if not config.wrapped:
        return []
    data = copy.deepcopy(config.data)
    servers = data["mcpServers"]
    for server in config.wrapped:
        servers[server.name] = unwrap_entry(servers[server.name])
    write_atomic(config.path, _dump(data, config.original))
    return [server.name for server in config.wrapped]


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
    "STARTER_CONFIG",
    "AppName",
    "ConfigPlan",
    "InstallError",
    "ServerPlan",
    "apply_init",
    "apply_unwrap_in_place",
    "backup",
    "config_paths",
    "default_airlock_command",
    "is_wrapped",
    "latest_backup",
    "plan",
    "read_config",
    "restore",
    "starter_config_path",
    "unwrap_entry",
    "wrap_entry",
    "write_atomic",
    "write_starter_config",
]
