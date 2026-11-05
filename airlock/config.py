"""Configuration management for Airlock."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


class ConfigError(Exception):
    """Raised when configuration loading or validation fails."""


class ClassifierConfig(BaseModel):
    """Configuration for the optional L2 ONNX classifier."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    required: bool = False
    model_name: Literal["22M", "86M"] = "22M"
    cache_size: int = Field(default=1024, ge=0)
    block_threshold: float = Field(default=0.8, ge=0, le=1)


class ThresholdOverride(BaseModel):
    """Per-source detector decision thresholds."""

    model_config = ConfigDict(extra="forbid")

    redact_above: float | None = Field(default=None, ge=0, le=1)
    block_above: float | None = Field(default=None, ge=0, le=1)


class TaintConfig(BaseModel):
    """Settings for the per-session taint tracker."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    max_entries: int = Field(default=10_000, gt=0)
    ttl_seconds: float = Field(default=3600.0, ge=0, description="0 disables expiry.")
    min_token_length: int = Field(default=16, ge=8)
    match_domains: bool = True


LabelName = Literal["source_untrusted", "source_secret", "sink"]
ArgRoleName = Literal["destination", "content", "path", "code"]


class LabelOverride(BaseModel):
    """A user label override under ``labels:``; wins over label packs and heuristics."""

    model_config = ConfigDict(extra="forbid")

    server: str = Field(default="*", description="Glob over server names.")
    tool: str = Field(min_length=1, description="Tool name or glob.")
    labels: list[LabelName] = Field(default_factory=list)
    args: dict[str, ArgRoleName] = Field(default_factory=dict)


def get_default_config_locations() -> tuple[Path, ...]:
    """Return default configuration search paths dynamically."""
    return (
        Path("airlock.yaml"),
        Path.home() / ".config" / "airlock" / "airlock.yaml",
    )


class AirlockConfig(BaseModel):
    """Airlock configuration settings."""

    model_config = ConfigDict(extra="forbid")

    mode: Literal["enforce", "shadow"] = "enforce"
    fail_mode: Literal["open", "closed"] = "closed"
    log_path: Path | None = None
    data_dir: Path = Field(default_factory=lambda: Path.home() / ".config" / "airlock")
    check_timeout_ms: int = Field(default=200, gt=0)
    auto_approve_new_tools: bool = False
    classifier: ClassifierConfig = Field(default_factory=ClassifierConfig)
    redact_above: float = Field(default=0.5, ge=0, le=1)
    block_above: float = Field(default=0.85, ge=0, le=1)
    spotlight: bool = False
    server_overrides: dict[str, ThresholdOverride] = Field(default_factory=dict)
    tool_overrides: dict[str, ThresholdOverride] = Field(default_factory=dict)
    labels: list[LabelOverride] = Field(default_factory=list)
    taint: TaintConfig = Field(default_factory=TaintConfig)
    trusted_values: list[str] = Field(default_factory=list)

    @field_validator("data_dir", "log_path", mode="before")
    @classmethod
    def _expand_path(cls, v: Any) -> Any:
        if isinstance(v, (str, Path)):
            return Path(v).expanduser()
        return v

    @classmethod
    def load(cls, config_path: Path | str | None = None) -> AirlockConfig:
        """Load configuration from explicit path or default search locations."""
        return load_config(config_path)


def find_config_path(explicit_path: Path | str | None = None) -> Path | None:
    """Resolve config file path according to search order."""
    if explicit_path is not None:
        path = Path(explicit_path).expanduser()
        if not path.is_file():
            raise ConfigError(f"Configuration file not found: {path}")
        return path

    for candidate in get_default_config_locations():
        expanded = candidate.expanduser()
        if expanded.is_file():
            return expanded

    return None


def load_config(config_path: Path | str | None = None) -> AirlockConfig:
    """Load and validate Airlock configuration.

    Search order:
    1. --config flag (explicit_path)
    2. ./airlock.yaml
    3. ~/.config/airlock/airlock.yaml

    If no config file is found and no explicit path was provided, defaults are used.
    """
    resolved_path = find_config_path(config_path)
    if resolved_path is None:
        return AirlockConfig()

    try:
        with open(resolved_path, encoding="utf-8") as f:
            raw_data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in configuration file {resolved_path}: {exc}") from exc

    if raw_data is None:
        # File is empty; use defaults
        return AirlockConfig()

    if not isinstance(raw_data, dict):
        type_name = type(raw_data).__name__
        raise ConfigError(
            f"Configuration file at {resolved_path} must be a YAML mapping, got {type_name}"
        )

    try:
        return AirlockConfig.model_validate(raw_data)
    except ValidationError as exc:
        raise ConfigError(f"Configuration validation failed for {resolved_path}: {exc}") from exc


__all__ = [
    "AirlockConfig",
    "ClassifierConfig",
    "ConfigError",
    "LabelOverride",
    "TaintConfig",
    "ThresholdOverride",
    "find_config_path",
    "get_default_config_locations",
    "load_config",
]
