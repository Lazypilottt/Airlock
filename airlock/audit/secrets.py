"""Secret masking and preview sanitization utilities."""

from __future__ import annotations

import json
import re
from typing import Any

# Common secret patterns:
# - AWS access keys (e.g. AKIA...)
# - GitHub personal/oauth tokens
# - Bearer authorization tokens
# - PEM Private key blocks
# - High-entropy keys adjacent to sensitive keywords (api_key, token, secret, password)
SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Private key PEM blocks
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.MULTILINE,
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    # AWS access key IDs
    (
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "[REDACTED_AWS_KEY]",
    ),
    # GitHub tokens
    (
        re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b"),
        "[REDACTED_GITHUB_TOKEN]",
    ),
    # Vendor key formats: OpenAI/Anthropic-style sk-, Stripe sk_/rk_, Slack xox*-,
    # Google AIza..., JSON Web Tokens
    (
        re.compile(r"\b(?:sk|rk)[-_](?:[A-Za-z]+[-_])?[A-Za-z0-9_-]{16,}"),
        "[REDACTED_API_KEY]",
    ),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "[REDACTED_SLACK_TOKEN]"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "[REDACTED_GOOGLE_KEY]"),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
        "[REDACTED_JWT]",
    ),
    # Bearer authorization tokens
    (
        re.compile(r"(?i)(\bbearer\s+)([A-Za-z0-9_\-\.~+/]+=*)"),
        r"\1[REDACTED_BEARER_TOKEN]",
    ),
    # Sensitive keyword assignments with tokens/secrets/passwords (handles JSON and YAML formats)
    (
        re.compile(
            r"""(?ix)
            (['"]?)\b((?:[A-Za-z0-9]+[_-])*(?:api[_-]?key|access[_-]?token|auth[_-]?token|token|secret|password|passwd|private[_-]?key|key))\b\1
            (\s*[:=]\s*['"]?)
            ([A-Za-z0-9_\-\.~+/]{16,})
            (['"]?)
            """
        ),
        r"\1\2\1\3[REDACTED_SECRET]\5",
    ),
    # High-entropy strings anywhere: 24+ characters mixing lower case, upper case
    # and digits (random keys, passwords, honeytokens). Hex hashes and words are
    # left alone; previews lose a little detail, which is the safe trade-off.
    (
        re.compile(
            r"(?<![A-Za-z0-9+/_-])(?=[A-Za-z0-9+/_-]{24,})(?=[^\s]*?[a-z])(?=[^\s]*?[A-Z])"
            r"(?=[^\s]*?[0-9])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/_-])"
        ),
        "[REDACTED_HIGH_ENTROPY]",
    ),
]


def mask_secrets(text: str) -> str:
    """Mask known secret patterns with redaction placeholders."""
    if not text:
        return ""

    sanitized = text
    for pattern, replacement in SECRET_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def sanitize_preview(data: Any, max_length: int = 500) -> str:
    """Format, mask secrets, and truncate preview string to max_length characters."""
    if data is None:
        return ""

    if isinstance(data, (dict, list)):
        try:
            raw_text = json.dumps(data, ensure_ascii=False, default=str)
        except Exception:
            raw_text = str(data)
    else:
        raw_text = str(data)

    masked = mask_secrets(raw_text)

    if len(masked) > max_length:
        return masked[:max_length]

    return masked


__all__ = [
    "SECRET_PATTERNS",
    "mask_secrets",
    "sanitize_preview",
]
