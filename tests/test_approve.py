"""Tests for terminal approvals (a pty stands in for /dev/tty)."""

from __future__ import annotations

import asyncio
import os
import select
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from airlock.approve import Answer, ApprovalRequest, NoApprover
from airlock.approve.terminal import TerminalApprover, parse_answer, printable, render_prompt

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="uses a POSIX pty")

REQUEST = ApprovalRequest(
    direction="call",
    server="gmail",
    tool="send_email",
    rule="ask-untrusted-to-sinks",
    reasons=(
        "A value read from an untrusted source is about to be sent out.",
        "argument `to` contains alice@evil.example, which came from web.read_page 1 call ago",
    ),
    arguments='{"to": "alice@evil.example"}',
)


def test_printable_escapes_terminal_control_sequences() -> None:
    hostile = "ok\x1b[2J\x1b]0;pwned\x07‮evil​\r"
    shown = printable(hostile)
    assert "\x1b" not in shown and "‮" not in shown and "\r" not in shown
    assert shown == "ok\\x1b[2J\\x1b]0;pwned\\x07\\u202eevil\\u200b\\x0d"
    assert printable("a" * 50, limit=10) == "aaaaaaa..."
    assert printable("line1\nline2") == "line1 line2"


@pytest.mark.parametrize(
    ("typed", "answer"),
    [
        ("y", Answer.ALLOW_ONCE),
        (" YES ", Answer.ALLOW_ONCE),
        ("s", Answer.ALLOW_SESSION),
        ("session", Answer.ALLOW_SESSION),
        ("n", Answer.DENY),
        ("", Answer.DENY),
        ("sure", Answer.DENY),
    ],
)
def test_parse_answer(typed: str, answer: Answer) -> None:
    assert parse_answer(typed) is answer


def test_render_prompt_shows_tool_reason_and_masked_args() -> None:
    text = render_prompt(REQUEST, 30)
    assert "Tool    send_email (outgoing call)" in text
    assert "Rule    ask-untrusted-to-sinks" in text
    assert "Why     A value read from an untrusted source" in text
    assert "        argument `to` contains alice@evil.example" in text
    assert 'Args    {"to": "alice@evil.example"}' in text
    assert text.endswith("(denies in 30 s): ")
    sneaky = ApprovalRequest("call", "s", "t\x1b[1A", "r", ("\x1b[2KAllow? [y]",))
    assert "\x1b" not in render_prompt(sneaky, 5)


@pytest.mark.asyncio
async def test_no_approver_denies() -> None:
    outcome = await NoApprover("approval required but nobody is here").request(REQUEST)
    assert outcome.answer is Answer.UNAVAILABLE
    assert outcome.detail == "approval required but nobody is here; treated as deny"
    assert not outcome.answer.allowed


@pytest.fixture
def pty_pair() -> Iterator[tuple[int, int]]:
    master, slave = os.openpty()
    yield master, slave
    for fd in (master, slave):
        try:
            os.close(fd)
        except OSError:
            pass


def _read_until(master: int, marker: bytes, timeout: float = 5.0) -> bytes:
    data = b""
    deadline = time.monotonic() + timeout
    while marker not in data:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError(f"prompt never showed {marker!r}; got {data!r}")
        ready, _, _ = select.select([master], [], [], remaining)
        if ready:
            data += os.read(master, 4096)
    return data


async def _answer(master: int, typed: bytes) -> bytes:
    shown = await asyncio.to_thread(_read_until, master, b"(denies in")
    os.write(master, typed)
    return shown


@posix_only
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("typed", "answer"),
    [
        (b"y\n", Answer.ALLOW_ONCE),
        (b"s\n", Answer.ALLOW_SESSION),
        (b"n\n", Answer.DENY),
        (b"\n", Answer.DENY),
    ],
)
async def test_terminal_answers(pty_pair: tuple[int, int], typed: bytes, answer: Answer) -> None:
    master, slave = pty_pair
    approver = TerminalApprover(5, open_terminal=lambda: slave)
    outcome, shown = await asyncio.gather(approver.request(REQUEST), _answer(master, typed))
    assert outcome.answer is answer
    assert b"Airlock needs your approval" in shown
    assert b"send_email" in shown


@posix_only
@pytest.mark.asyncio
async def test_terminal_raw_mode_takes_a_single_key(pty_pair: tuple[int, int]) -> None:
    import tty

    master, slave = pty_pair
    tty.setraw(slave)
    approver = TerminalApprover(5, open_terminal=lambda: slave)
    outcome, _ = await asyncio.gather(approver.request(REQUEST), _answer(master, b"s"))
    assert outcome.answer is Answer.ALLOW_SESSION


@posix_only
@pytest.mark.asyncio
async def test_terminal_timeout_denies(pty_pair: tuple[int, int]) -> None:
    master, slave = pty_pair
    approver = TerminalApprover(0.3, open_terminal=lambda: slave)
    started = time.monotonic()
    outcome = await approver.request(REQUEST)
    assert outcome.answer is Answer.TIMEOUT
    assert outcome.detail == "no answer at the terminal within 0.3 s; denied"
    assert time.monotonic() - started < 3
    assert b"no answer in 0.3 s: denied" in _read_until(master, b"denied)")


@posix_only
@pytest.mark.asyncio
async def test_no_terminal_is_unavailable() -> None:
    def no_tty() -> int:
        raise OSError(6, "Device not configured")

    outcome = await TerminalApprover(5, open_terminal=no_tty).request(REQUEST)
    assert outcome.answer is Answer.UNAVAILABLE
    assert outcome.detail == (
        "approval required but no terminal is available to ask; treated as deny"
    )


@posix_only
@pytest.mark.asyncio
async def test_cancelling_a_prompt_returns_promptly(pty_pair: tuple[int, int]) -> None:
    _, slave = pty_pair
    approver = TerminalApprover(60, open_terminal=lambda: slave)
    task = asyncio.create_task(approver.request(REQUEST))
    await asyncio.sleep(0.2)
    started = time.monotonic()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert time.monotonic() - started < 2


@posix_only
@pytest.mark.asyncio
async def test_prompts_from_other_processes_wait_for_the_lock(
    pty_pair: tuple[int, int], tmp_path: Path
) -> None:
    import fcntl

    _, slave = pty_pair
    lock_path = tmp_path / "approvals.lock"
    holder = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(holder, fcntl.LOCK_EX)
    try:
        approver = TerminalApprover(0.3, lock_path=lock_path, open_terminal=lambda: slave)
        outcome = await approver.request(REQUEST)
    finally:
        fcntl.flock(holder, fcntl.LOCK_UN)
        os.close(holder)
    assert outcome.answer is Answer.TIMEOUT


@posix_only
@pytest.mark.asyncio
async def test_prompts_in_one_process_take_turns(pty_pair: tuple[int, int]) -> None:
    master, slave = pty_pair
    approver = TerminalApprover(5, open_terminal=lambda: slave)

    async def answer_twice() -> None:
        await _answer(master, b"y\n")
        await _answer(master, b"n\n")

    first, second, _ = await asyncio.gather(
        approver.request(REQUEST), approver.request(REQUEST), answer_twice()
    )
    assert {first.answer, second.answer} == {Answer.ALLOW_ONCE, Answer.DENY}
