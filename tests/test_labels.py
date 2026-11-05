"""Tests for tool labels: packs, globs, precedence, heuristics and storage."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from airlock.cli import app
from airlock.config import AirlockConfig, ConfigError, LabelOverride, load_config
from airlock.engine import Engine
from airlock.models import ToolDef
from airlock.registry.labels import (
    ArgRole,
    Label,
    LabelError,
    LabelOrigin,
    LabelPack,
    LabelResolver,
    builtin_label_packs_dir,
    infer_labels,
    load_label_packs,
)
from airlock.registry.store import ToolRegistry

runner = CliRunner(env={"COLUMNS": "200"})

U = Label.SOURCE_UNTRUSTED
S = Label.SOURCE_SECRET
K = Label.SINK


def tool(name: str, description: str = "", props: tuple[str, ...] = ()) -> ToolDef:
    return ToolDef(
        server_id="srv",
        name=name,
        description=description,
        input_schema={"type": "object", "properties": {p: {"type": "string"} for p in props}},
    )


# ---------------------------------------------------------------------------
# Pack loading
# ---------------------------------------------------------------------------


def test_builtin_packs_load_and_cover_required_servers() -> None:
    packs = load_label_packs()
    names = {pack.name for pack in packs}
    assert {"filesystem", "fetch", "github", "slack", "playwright"} <= names
    for pack in packs:
        assert pack.servers
        assert pack.tools
        assert pack.source.startswith("https://")


def test_builtin_pack_dir_exists() -> None:
    assert builtin_label_packs_dir().is_dir()


def test_pack_without_servers_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("name: bad\nservers: []\ntools: []\n", encoding="utf-8")
    with pytest.raises(LabelError):
        LabelPack.load(path)


def test_pack_with_unknown_label_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(
        "name: bad\nservers: [x]\ntools:\n  - tool: t\n    labels: [exfiltrator]\n",
        encoding="utf-8",
    )
    with pytest.raises(LabelError):
        LabelPack.load(path)


def test_pack_with_unknown_arg_role_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(
        "name: bad\nservers: [x]\ntools:\n  - tool: t\n    labels: [sink]\n"
        "    args: {to: target}\n",
        encoding="utf-8",
    )
    with pytest.raises(LabelError):
        LabelPack.load(path)


def test_pack_that_is_not_a_mapping_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("- just a list\n", encoding="utf-8")
    with pytest.raises(LabelError):
        LabelPack.load(path)


def test_custom_pack_directory(tmp_path: Path) -> None:
    (tmp_path / "mail.yaml").write_text(
        "name: mail\nservers: [mail]\ntools:\n"
        "  - tool: deliver\n    labels: [sink]\n    args: {rcpt: destination}\n",
        encoding="utf-8",
    )
    resolver = LabelResolver(packs=load_label_packs(tmp_path))
    labels = resolver.resolve("mail", tool("deliver"))
    assert labels.labels == {K}
    assert labels.origin is LabelOrigin.PACK
    assert labels.source == "mail"
    assert labels.arg_roles == {"rcpt": ArgRole.DESTINATION}


def test_missing_pack_directory_gives_no_packs(tmp_path: Path) -> None:
    assert load_label_packs(tmp_path / "nope") == []


# ---------------------------------------------------------------------------
# Glob matching
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("server", "tool_name", "expected"),
    [
        ("github", "create_branch", {K}),  # create_* glob
        ("github", "label_write", {K}),  # *_write glob
        ("github", "list_issues", {U}),  # list_* glob
        ("github", "pull_request_read", {U}),  # *_read glob
        ("github", "get_secret_scanning_alert", {U, S}),  # exact beats get_*
        ("github", "get_me", set()),  # exact empty entry beats get_*
        ("playwright", "browser_verify_text_visible", {U}),
        ("playwright", "browser_mouse_click_xy", {K}),
        ("playwright", "browser_cookie_delete", {K}),  # browser_*_delete before browser_*
        ("playwright", "browser_resize", set()),  # catch-all browser_*
        ("fetch", "fetch", {U, K}),
        ("filesystem", "write_file", {K}),
        ("filesystem", "read_text_file", {U}),
        ("slack", "conversations_add_message", {K}),
        ("slack", "slack_get_channel_history", {U}),
    ],
)
def test_pack_globs(server: str, tool_name: str, expected: set[Label]) -> None:
    labels = LabelResolver().resolve(server, tool(tool_name))
    assert labels.labels == expected
    assert labels.origin is LabelOrigin.PACK


@pytest.mark.parametrize("server", ["github", "GitHub", "my-github-server", "gh"])
def test_server_globs_are_case_insensitive(server: str) -> None:
    labels = LabelResolver().resolve(server, tool("issue_write"))
    assert labels.source == "github"


def test_pack_does_not_apply_to_other_servers() -> None:
    labels = LabelResolver().resolve("notes", tool("get_me"))
    assert labels.origin is not LabelOrigin.PACK


def test_pack_arg_roles() -> None:
    labels = LabelResolver().resolve("slack", tool("slack_post_message"))
    assert labels.arg_roles == {"channel_id": ArgRole.DESTINATION, "text": ArgRole.CONTENT}
    assert LabelResolver().resolve("fetch", tool("fetch")).arg_roles == {"url": ArgRole.DESTINATION}


# ---------------------------------------------------------------------------
# Precedence: user > pack > heuristic
# ---------------------------------------------------------------------------


def test_user_override_beats_pack() -> None:
    resolver = LabelResolver(
        user_entries=[
            LabelOverride(
                server="filesystem",
                tool="read_*",
                labels=["source_untrusted", "source_secret"],
            )
        ]
    )
    labels = resolver.resolve("filesystem", tool("read_text_file"))
    assert labels.labels == {U, S}
    assert labels.origin is LabelOrigin.USER
    assert labels.source == "airlock.yaml"
    # Other tools on the server still come from the pack.
    assert resolver.resolve("filesystem", tool("write_file")).origin is LabelOrigin.PACK


def test_user_override_beats_heuristic_and_can_clear_labels() -> None:
    resolver = LabelResolver(user_entries=[LabelOverride(tool="send_email", labels=[])])
    labels = resolver.resolve("mailer", tool("send_email"))
    assert labels.labels == frozenset()
    assert labels.origin is LabelOrigin.USER


def test_user_override_server_glob_limits_scope() -> None:
    resolver = LabelResolver(
        user_entries=[LabelOverride(server="internal-*", tool="send_email", labels=[])]
    )
    assert resolver.resolve("internal-mail", tool("send_email")).origin is LabelOrigin.USER
    assert resolver.resolve("mail", tool("send_email")).origin is LabelOrigin.INFERRED


def test_user_exact_tool_beats_user_glob() -> None:
    resolver = LabelResolver(
        user_entries=[
            LabelOverride(tool="*", labels=["sink"]),
            LabelOverride(tool="lookup", labels=["source_untrusted"]),
        ]
    )
    assert resolver.resolve("x", tool("lookup")).labels == {U}
    assert resolver.resolve("x", tool("other")).labels == {K}


def test_user_override_arg_roles() -> None:
    resolver = LabelResolver(
        user_entries=[LabelOverride(tool="notify", labels=["sink"], args={"who": "destination"})]
    )
    assert resolver.resolve("x", tool("notify")).arg_roles == {"who": ArgRole.DESTINATION}


def test_pack_beats_heuristic() -> None:
    # The heuristic would call get_secret_scanning_alert a secret source only;
    # the pack also marks it untrusted.
    heuristic = infer_labels(tool("get_secret_scanning_alert"))
    pack = LabelResolver().resolve("github", tool("get_secret_scanning_alert"))
    assert heuristic.labels != pack.labels
    assert pack.origin is LabelOrigin.PACK


def test_heuristic_fallback_for_tool_missing_from_pack() -> None:
    labels = LabelResolver().resolve("slack", tool("send_direct_message"))
    assert labels.origin is LabelOrigin.INFERRED
    assert labels.labels == {K}


def test_heuristics_can_be_disabled() -> None:
    labels = LabelResolver(use_heuristics=False).resolve("x", tool("send_email"))
    assert labels.labels == frozenset()
    assert labels.origin is LabelOrigin.NONE


# ---------------------------------------------------------------------------
# Heuristic table
# ---------------------------------------------------------------------------

HEURISTIC_CASES: list[tuple[str, str, tuple[str, ...], set[Label]]] = [
    ("send_email", "Send an email", ("to", "body"), {K}),
    ("post_message", "Post a message to a channel", ("channel", "text"), {K}),
    ("send_slack_message", "Send a Slack message", ("channel", "text"), {K}),
    ("execute_command", "Run a shell command", ("command",), {K}),
    ("delete_file", "Delete a file", ("path",), {K}),
    ("createIssue", "Create a GitHub issue", ("title", "body"), {K}),
    ("write_note", "Write a note", ("text",), {K}),
    ("upload_document", "Upload a document", ("path",), {K}),
    ("transfer_money", "Transfer money", ("iban", "amount"), {K}),
    ("notify_user", "", ("recipient", "message"), {K}),
    ("run_query", "Run a SQL query on the database", ("sql",), {K}),
    ("dispatch", "Dispatch a job", ("to", "payload"), {K}),  # schema has `to`
    ("http_request", "Make an HTTP request", ("url", "method", "body"), {U, K}),
    ("fetch_url", "", ("url",), {U}),
    ("read_page", "Return canned page text", ("url",), {U}),
    ("search_web", "Search the web", ("query",), {U}),
    ("list_issues", "List issues in a repository", ("repo",), {U}),
    ("get_post", "Get a blog post", ("id",), {U}),
    ("list_comments", "List comments on a ticket", ("ticket",), {U}),
    ("browse", "Open a web page", ("url",), {U}),
    ("read_inbox", "Read the latest emails", (), {U}),
    ("get_document", "", ("doc_id",), {U}),
    ("open_link", "Open a link", ("url",), {U}),
    ("get_env", "Read environment variables", (), {S}),
    ("read_dotenv", "Read the project's .env file", (), {S}),
    ("read_ssh_key", "Read ~/.ssh/id_rsa", (), {S}),
    ("get_api_key", "", (), {S}),
    ("get_cookies", "Return browser cookies", (), {S}),
    ("list_credentials", "List stored credentials", (), {S}),
    ("vault_read", "Read a value from the vault", ("key",), {S}),
    ("echo", "Return text unchanged", ("text",), set()),
    ("get_weather", "Get the weather forecast for a city", ("city",), set()),
    ("calculate_sum", "Calculate the sum of two numbers", ("a", "b"), set()),
    ("read_file", "Read a file from disk", ("path",), set()),
    ("get_time", "Get the current time", (), set()),
    ("list_tools", "List available tools", (), set()),
]


@pytest.mark.parametrize(("name", "description", "props", "expected"), HEURISTIC_CASES)
def test_heuristic_table(
    name: str, description: str, props: tuple[str, ...], expected: set[Label]
) -> None:
    labels = infer_labels(tool(name, description, props))
    assert labels.labels == expected
    if expected:
        assert labels.origin is LabelOrigin.INFERRED
        assert labels.reasons
    else:
        assert labels.origin is LabelOrigin.NONE


def test_heuristic_arg_roles_for_sinks() -> None:
    labels = infer_labels(tool("send_email", "Send", ("to", "subject", "body", "attachment")))
    assert labels.arg_roles == {
        "to": ArgRole.DESTINATION,
        "subject": ArgRole.CONTENT,
        "body": ArgRole.CONTENT,
    }
    assert infer_labels(tool("run_shell", "", ("command",))).arg_roles == {"command": ArgRole.CODE}


def test_heuristic_does_not_assign_arg_roles_to_sources() -> None:
    assert infer_labels(tool("fetch_url", "", ("url",))).arg_roles == {}


def test_heuristic_tolerates_odd_schema() -> None:
    odd = ToolDef(server_id="s", name="send_it", description="", input_schema={"properties": []})
    assert infer_labels(odd).labels == {K}


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def test_config_labels_parse(tmp_path: Path) -> None:
    path = tmp_path / "airlock.yaml"
    path.write_text(
        "labels:\n"
        "  - server: filesystem\n"
        "    tool: 'read_*'\n"
        "    labels: [source_untrusted, source_secret]\n"
        "  - tool: deploy\n"
        "    labels: [sink]\n"
        "    args: {target: destination}\n",
        encoding="utf-8",
    )
    config = load_config(path)
    assert config.labels[0].server == "filesystem"
    assert config.labels[1].server == "*"
    assert config.labels[1].args == {"target": "destination"}


def test_config_rejects_unknown_label(tmp_path: Path) -> None:
    path = tmp_path / "airlock.yaml"
    path.write_text("labels:\n  - tool: x\n    labels: [exfil]\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


# ---------------------------------------------------------------------------
# Registry storage and engine
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_engine_stores_labels_and_origin(tmp_path: Path) -> None:
    config = AirlockConfig(
        data_dir=tmp_path,
        labels=[LabelOverride(server="github", tool="get_me", labels=["source_secret"])],
    )
    engine = Engine(config=config)
    await engine.on_tools_listed(
        "github",
        [tool("issue_write"), tool("get_me"), tool("totally_new_send_tool")],
    )
    await engine.on_tools_listed("helper", [tool("echo")])

    issue = engine.labels_for("github", "issue_write")
    assert issue.labels == {K}
    assert issue.origin is LabelOrigin.PACK
    assert issue.source == "github"
    assert issue.arg_roles["body"] is ArgRole.CONTENT

    me = engine.labels_for("github", "get_me")
    assert me.labels == {S}
    assert me.origin is LabelOrigin.USER

    new = engine.labels_for("github", "totally_new_send_tool")
    assert new.labels == {K}
    assert new.origin is LabelOrigin.INFERRED

    assert engine.labels_for("helper", "echo").labels == frozenset()
    assert engine.labels_for("nowhere", "nothing").origin is LabelOrigin.NONE
    await engine.close()


@pytest.mark.asyncio
async def test_labels_refresh_when_config_changes(tmp_path: Path) -> None:
    engine = Engine(config=AirlockConfig(data_dir=tmp_path))
    await engine.on_tools_listed("mail", [tool("send_email")])
    assert engine.labels_for("mail", "send_email").origin is LabelOrigin.INFERRED

    engine.label_resolver = LabelResolver(
        user_entries=[LabelOverride(tool="send_email", labels=["sink", "source_secret"])]
    )
    await engine.on_tools_listed("mail", [tool("send_email")])
    refreshed = engine.labels_for("mail", "send_email")
    assert refreshed.origin is LabelOrigin.USER
    assert refreshed.labels == {K, S}
    await engine.close()


def test_registry_migrates_old_schema(tmp_path: Path) -> None:
    db = tmp_path / "registry.db"
    conn = sqlite3.connect(db)
    conn.execute(
        """
        CREATE TABLE tools (
            server_id TEXT NOT NULL, tool_name TEXT NOT NULL, hash TEXT NOT NULL,
            definition_json TEXT NOT NULL, previous_definition_json TEXT,
            first_seen REAL NOT NULL, last_seen REAL NOT NULL, status TEXT NOT NULL,
            status_reason TEXT, labels TEXT NOT NULL,
            PRIMARY KEY (server_id, tool_name)
        )
        """
    )
    conn.execute(
        "INSERT INTO tools VALUES ('s', 't', 'h', '{}', NULL, 0, 0, 'approved', NULL, '[]')"
    )
    conn.commit()
    conn.close()

    registry = ToolRegistry(db)
    labels = registry.get_labels("s", "t")
    assert labels is not None
    assert labels.origin is LabelOrigin.NONE
    assert labels.labels == frozenset()


def test_corrupt_label_columns_are_tolerated(tmp_path: Path) -> None:
    registry = ToolRegistry(tmp_path / "registry.db")
    conn = sqlite3.connect(tmp_path / "registry.db")
    conn.execute(
        "INSERT INTO tools (server_id, tool_name, hash, definition_json, first_seen, last_seen,"
        " status, labels, label_origin, label_source, arg_roles)"
        " VALUES ('s', 't', 'h', '{}', 0, 0, 'approved', 'not json', 'weird', 'x', '[1]')"
    )
    conn.commit()
    conn.close()
    labels = registry.get_labels("s", "t")
    assert labels is not None
    assert labels.labels == frozenset()
    assert labels.origin is LabelOrigin.NONE
    assert labels.arg_roles == {}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _config_file(tmp_path: Path) -> Path:
    path = tmp_path / "airlock.yaml"
    path.write_text(f"data_dir: {tmp_path}\n", encoding="utf-8")
    return path


@pytest.mark.asyncio
async def test_tools_list_shows_labels_and_origin(tmp_path: Path) -> None:
    engine = Engine(config=AirlockConfig(data_dir=tmp_path))
    await engine.on_tools_listed("fetch", [tool("fetch")])
    await engine.on_tools_listed("mail", [tool("send_email")])
    await engine.close()

    config = _config_file(tmp_path)
    result = runner.invoke(app, ["tools", "list", "--config", str(config)])
    assert result.exit_code == 0, result.output
    assert "sink, source_untrusted" in result.output
    assert "pack:fetch" in result.output
    assert "inferred" in result.output

    result = runner.invoke(app, ["tools", "list", "--json", "--config", str(config)])
    assert result.exit_code == 0
    rows: list[dict[str, Any]] = json.loads(result.output)
    by_tool = {row["tool_name"]: row for row in rows}
    assert by_tool["fetch"]["labels"] == ["sink", "source_untrusted"]
    assert by_tool["fetch"]["label_origin"] == "pack"
    assert by_tool["fetch"]["label_source"] == "fetch"
    assert by_tool["fetch"]["arg_roles"] == {"url": "destination"}
    assert by_tool["send_email"]["label_origin"] == "inferred"
