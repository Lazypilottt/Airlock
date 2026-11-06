"""Fake secrets that look real but cannot work anywhere.

Each format is broken on purpose in a way the real issuer checks:

- **AWS access key ID**: ``AKIA`` plus 16 characters. Real key IDs use only
  ``A-Z`` and ``2-7`` (base32); every fake one contains a ``0``, ``1``, ``8``
  or ``9``, so it can never be issued.
- **GitHub token**: ``ghp_`` plus 30 random base62 characters plus a 6-character
  CRC32 checksum. GitHub rejects tokens whose checksum does not match; ours is
  always off by one.
- **Database password and canary URL**: random values pointing at
  ``127.0.0.1``, which only reach this machine.
"""

from __future__ import annotations

import secrets
import string
import time
import zlib
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any, Literal

TokenKind = Literal[
    "aws_access_key_id",
    "aws_secret_access_key",
    "github_token",
    "database_password",
    "canary_url",
]

_BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_NOT_BASE32 = "0189"
_BASE62 = string.digits + string.ascii_uppercase + string.ascii_lowercase
_ALNUM = string.ascii_letters + string.digits
DEFAULT_CANARY_PORT = 47801


@dataclass(frozen=True)
class Honeytoken:
    """One planted fake secret.

    ``value`` is what gets planted; ``needle`` is the part that is searched for
    in outbound calls (the random part of a URL, so a rewritten URL still hits).
    """

    id: str
    set_id: str
    kind: TokenKind
    value: str
    needle: str
    created_at: float

    def to_record(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> Honeytoken:
        return cls(
            id=str(record["id"]),
            set_id=str(record["set_id"]),
            kind=record["kind"],
            value=str(record["value"]),
            needle=str(record.get("needle") or record["value"]),
            created_at=float(record.get("created_at", 0.0)),
        )


def _random(alphabet: str, length: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(length))


def fake_aws_access_key_id() -> str:
    """``AKIA`` + 16 characters, at least one of which no real key ID can contain."""
    body = list(_random(_BASE32, 16))
    body[secrets.randbelow(16)] = secrets.choice(_NOT_BASE32)
    return "AKIA" + "".join(body)


def is_impossible_aws_key_id(value: str) -> bool:
    """True if ``value`` has the AWS key ID shape but a character AWS never uses."""
    return (
        len(value) == 20
        and value.startswith("AKIA")
        and all(char in _BASE32 + _NOT_BASE32 for char in value[4:])
        and any(char in _NOT_BASE32 for char in value[4:])
    )


def fake_aws_secret_access_key() -> str:
    # Real secrets also use "+" and "/"; letters and digits survive URL encoding unchanged.
    return _random(_ALNUM, 40)


def _base62(number: int, width: int) -> str:
    digits: list[str] = []
    while number:
        number, remainder = divmod(number, 62)
        digits.append(_BASE62[remainder])
    return "".join(reversed(digits)).rjust(width, "0")


def github_checksum(body: str) -> str:
    """The checksum GitHub appends to a token body (CRC32, base62, 6 characters)."""
    return _base62(zlib.crc32(body.encode("ascii")), 6)


def fake_github_token() -> str:
    """``ghp_`` + 30 random characters + a checksum that is deliberately wrong."""
    body = _random(_BASE62, 30)
    wrong = (zlib.crc32(body.encode("ascii")) + 1) % (1 << 32)
    return f"ghp_{body}{_base62(wrong, 6)}"


def has_valid_github_checksum(token: str) -> bool:
    body, checksum = token[4:-6], token[-6:]
    return github_checksum(body) == checksum


def create_set(
    canary_port: int = DEFAULT_CANARY_PORT, now: float | None = None
) -> list[Honeytoken]:
    """A fresh set: AWS key pair, GitHub token, database password and canary URL."""
    created = time.time() if now is None else now
    set_id = datetime.fromtimestamp(created, UTC).strftime("%Y%m%d") + "-" + secrets.token_hex(3)
    canary_id = secrets.token_hex(12)
    db_password = _random(_ALNUM, 24)

    def token(kind: TokenKind, value: str, needle: str | None = None) -> Honeytoken:
        return Honeytoken(
            id=f"{set_id}/{kind}",
            set_id=set_id,
            kind=kind,
            value=value,
            needle=needle or value,
            created_at=created,
        )

    return [
        token("aws_access_key_id", fake_aws_access_key_id()),
        token("aws_secret_access_key", fake_aws_secret_access_key()),
        token("github_token", fake_github_token()),
        token(
            "database_password",
            f"postgres://airlock_decoy:{db_password}@127.0.0.1:5432/decoy",
            db_password,
        ),
        token("canary_url", f"http://127.0.0.1:{canary_port}/canary/{canary_id}", canary_id),
    ]


def _header(comment: str, created: float) -> str:
    day = datetime.fromtimestamp(created, UTC).strftime("%Y-%m-%d")
    return (
        f"{comment} FAKE CREDENTIALS created by Airlock on {day} as honeytokens.\n"
        f"{comment} They are not valid for any service. If one appears in an outgoing\n"
        f"{comment} tool call, Airlock blocks the call and raises an alert.\n"
    )


def _by_kind(tokens: list[Honeytoken]) -> dict[str, str]:
    return {token.kind: token.value for token in tokens}


def render_env(tokens: list[Honeytoken]) -> str:
    """A decoy ``.env`` file."""
    values = _by_kind(tokens)
    return _header("#", tokens[0].created_at) + (
        f"AWS_ACCESS_KEY_ID={values['aws_access_key_id']}\n"
        f"AWS_SECRET_ACCESS_KEY={values['aws_secret_access_key']}\n"
        f"GITHUB_TOKEN={values['github_token']}\n"
        f"DATABASE_URL={values['database_password']}\n"
        f"BACKUP_WEBHOOK_URL={values['canary_url']}\n"
    )


def render_aws_credentials(tokens: list[Honeytoken]) -> str:
    """A decoy ``~/.aws/credentials``-style file."""
    values = _by_kind(tokens)
    return _header("#", tokens[0].created_at) + (
        "[default]\n"
        f"aws_access_key_id = {values['aws_access_key_id']}\n"
        f"aws_secret_access_key = {values['aws_secret_access_key']}\n"
    )


def render_decoy(filename: str, tokens: list[Honeytoken]) -> str:
    """Decoy content for a file name: AWS credentials format for ``credentials``, else ``.env``."""
    if filename == "credentials" or filename.endswith(".credentials"):
        return render_aws_credentials(tokens)
    return render_env(tokens)


__all__ = [
    "DEFAULT_CANARY_PORT",
    "Honeytoken",
    "TokenKind",
    "create_set",
    "fake_aws_access_key_id",
    "fake_aws_secret_access_key",
    "fake_github_token",
    "github_checksum",
    "has_valid_github_checksum",
    "is_impossible_aws_key_id",
    "render_aws_credentials",
    "render_decoy",
    "render_env",
]
