"""Tests for Airlock configuration loading and validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from airlock.config import AirlockConfig, ConfigError, load_config


def test_default_config_loads_with_no_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Default configuration loads cleanly when no config file exists."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "empty_home"))

    config = load_config()
    assert config.mode == "enforce"
    assert config.fail_mode == "closed"
    assert config.log_path is None
    assert config.data_dir == (tmp_path / "empty_home" / ".config" / "airlock")
    assert config.check_timeout_ms == 200


def test_sample_yaml_overrides_fields(tmp_path: Path) -> None:
    """Sample YAML file overrides default configuration fields."""
    sample_yaml = tmp_path / "custom.yaml"
    sample_yaml.write_text(
        """
mode: shadow
fail_mode: open
log_path: /tmp/custom_airlock.log
data_dir: /tmp/custom_data
check_timeout_ms: 150
""",
        encoding="utf-8",
    )

    config = load_config(sample_yaml)
    assert config.mode == "shadow"
    assert config.fail_mode == "open"
    assert config.log_path == Path("/tmp/custom_airlock.log")
    assert config.data_dir == Path("/tmp/custom_data")
    assert config.check_timeout_ms == 150


def test_config_search_order_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Config in current working directory is loaded when no explicit flag is passed."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))

    cwd_yaml = tmp_path / "airlock.yaml"
    cwd_yaml.write_text("mode: shadow\n", encoding="utf-8")

    config = load_config()
    assert config.mode == "shadow"
    assert config.fail_mode == "closed"


def test_config_search_order_home_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Config in ~/.config/airlock/airlock.yaml is loaded if no cwd config exists."""
    monkeypatch.chdir(tmp_path)
    fake_home = tmp_path / "home"
    config_dir = fake_home / ".config" / "airlock"
    config_dir.mkdir(parents=True)
    (config_dir / "airlock.yaml").write_text("fail_mode: open\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(fake_home))

    config = load_config()
    assert config.fail_mode == "open"
    assert config.mode == "enforce"


def test_invalid_yaml_syntax_gives_clear_error(tmp_path: Path) -> None:
    """Malformed YAML syntax raises a clear ConfigError."""
    bad_yaml = tmp_path / "syntax_error.yaml"
    bad_yaml.write_text("mode: [unclosed list", encoding="utf-8")

    with pytest.raises(ConfigError, match="Invalid YAML"):
        load_config(bad_yaml)


def test_invalid_yaml_values_give_clear_error(tmp_path: Path) -> None:
    """Invalid field values trigger a validation ConfigError."""
    bad_yaml = tmp_path / "invalid_values.yaml"
    bad_yaml.write_text("mode: super_enforce\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="validation failed"):
        load_config(bad_yaml)


def test_non_mapping_yaml_gives_clear_error(tmp_path: Path) -> None:
    """YAML file containing a non-mapping top-level element raises ConfigError."""
    bad_yaml = tmp_path / "non_dict.yaml"
    bad_yaml.write_text("- item1\n- item2\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="must be a YAML mapping"):
        load_config(bad_yaml)


def test_missing_explicit_config_gives_clear_error(tmp_path: Path) -> None:
    """Passing a nonexistent explicit config file raises ConfigError."""
    missing = tmp_path / "nonexistent.yaml"
    with pytest.raises(ConfigError, match="not found"):
        load_config(missing)


def test_empty_yaml_uses_defaults(tmp_path: Path) -> None:
    """An empty YAML file loads default configuration without errors."""
    empty_yaml = tmp_path / "empty.yaml"
    empty_yaml.write_text("", encoding="utf-8")

    config = load_config(empty_yaml)
    assert config == AirlockConfig()
