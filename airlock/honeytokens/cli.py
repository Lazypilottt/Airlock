"""``airlock honeytokens create`` and ``airlock honeytokens list``."""

from __future__ import annotations

import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer

from airlock.config import ConfigError, load_config
from airlock.honeytokens.store import HoneytokenStoreError, load, save, store_path
from airlock.honeytokens.tokens import DEFAULT_CANARY_PORT, create_set, render_decoy

honeytokens_app = typer.Typer(
    name="honeytokens",
    help="Plant fake secrets that Airlock blocks and alerts on if they are ever sent out.",
    no_args_is_help=True,
)

ConfigOption = Annotated[
    Path | None,
    typer.Option("--config", "-c", help="Path to airlock.yaml configuration file."),
]


def _fail(message: str) -> typer.Exit:
    sys.stderr.write(f"Error: {message}\n")
    return typer.Exit(code=1)


def _data_dir(config: Path | None) -> Path:
    try:
        return load_config(config).data_dir
    except ConfigError as exc:
        raise _fail(str(exc)) from exc


def _write_new_file(path: Path, content: str) -> None:
    """Create ``path`` (owner-only); fail if anything already exists there."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)


@honeytokens_app.command("create")
def create(
    write: Annotated[
        list[Path] | None,
        typer.Option(
            "--write",
            "-w",
            help="Also write a decoy file here (repeatable). `credentials` gets AWS format, "
            "anything else .env format. Existing files are never overwritten.",
        ),
    ] = None,
    yes: Annotated[
        bool, typer.Option("--yes", "-y", help="Write decoy files without asking.")
    ] = False,
    canary_port: Annotated[
        int,
        typer.Option("--canary-port", min=1, max=65535, help="Port for the localhost canary URL."),
    ] = DEFAULT_CANARY_PORT,
    config: ConfigOption = None,
) -> None:
    """Create a new set of honeytokens and optionally write decoy files."""
    path = store_path(_data_dir(config))
    try:
        data = load(path)
    except HoneytokenStoreError as exc:
        raise _fail(str(exc)) from exc
    tokens = create_set(canary_port=canary_port)
    data.tokens.extend(tokens)
    try:
        save(path, data)
    except OSError as exc:
        raise _fail(f"Cannot write {path}: {exc}") from exc

    print(f"Created honeytoken set {tokens[0].set_id} in {path}")
    print("These are fake and invalid for every service. Airlock denies any call carrying one.\n")
    for token in tokens:
        print(f"  {token.kind:<22} {token.value}")

    written = 0
    for target in write or []:
        target = target.expanduser()
        if target.exists() or target.is_symlink():
            print(f"\nSkipped {target}: it already exists (Airlock never overwrites files).")
            continue
        if not yes and not typer.confirm(f"\nWrite decoy file {target}?", default=False):
            print(f"Skipped {target}.")
            continue
        try:
            _write_new_file(target, render_decoy(target.name, tokens))
        except FileExistsError:
            print(f"Skipped {target}: it already exists (Airlock never overwrites files).")
            continue
        except OSError as exc:
            raise _fail(f"Cannot write {target}: {exc}") from exc
        data.decoys.append(
            {"path": str(target.resolve()), "set_id": tokens[0].set_id, "created_at": time.time()}
        )
        written += 1
        print(f"Wrote decoy file {target}")
    if written:
        save(path, data)
    else:
        print("\nTo plant the .env decoy, rerun with --write PATH, or copy the values above.")


@honeytokens_app.command("list")
def list_tokens(config: ConfigOption = None) -> None:
    """List planted honeytokens and decoy files."""
    path = store_path(_data_dir(config))
    try:
        data = load(path)
    except HoneytokenStoreError as exc:
        raise _fail(str(exc)) from exc
    if not data.tokens:
        print("No honeytokens yet. Create some with `airlock honeytokens create`.")
        return
    for token in data.tokens:
        day = datetime.fromtimestamp(token.created_at).strftime("%Y-%m-%d")
        print(f"{token.set_id}  {day}  {token.kind:<22} {token.value}")
    for decoy in data.decoys:
        print(f"decoy file: {decoy.get('path')} (set {decoy.get('set_id')})")


__all__ = ["honeytokens_app"]
