"""Ask a human on the controlling terminal.

In stdio mode stdin and stdout carry the MCP protocol, so the question goes to
``/dev/tty`` (macOS, Linux) or the console (``CONIN$``/``CONOUT$``, Windows).
Without a terminal the request is answered ``UNAVAILABLE`` and the caller
treats it as DENY.

Everything printed is untrusted (tool arguments, reasons quoting tool results),
so control and format characters are shown escaped: a tool result cannot move
the cursor, clear the screen or reorder text to fake the prompt.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import sys
import time
import unicodedata
from collections.abc import Callable, Iterator
from pathlib import Path

from airlock.approve import Answer, ApprovalOutcome, ApprovalRequest

_MAX_REASON = 300
_MAX_ARGS = 600
_POLL_SECONDS = 0.05

OpenTerminal = Callable[[], int]


def printable(text: str, limit: int | None = None) -> str:
    """Escape control and format characters (ANSI escapes, bidi overrides, zero-width)."""
    out: list[str] = []
    for char in text:
        if char == "\n":
            out.append(" ")
        elif unicodedata.category(char) in {"Cc", "Cf", "Co", "Cs"}:
            out.append(f"\\u{ord(char):04x}" if ord(char) > 0xFF else f"\\x{ord(char):02x}")
        else:
            out.append(char)
    shown = "".join(out)
    if limit is not None and len(shown) > limit:
        shown = shown[: limit - 3] + "..."
    return shown


def parse_answer(text: str) -> Answer:
    """``y``/``yes`` allow once, ``s``/``session`` allow for the session, anything else denies."""
    word = text.strip().lower()
    if word in {"y", "yes"}:
        return Answer.ALLOW_ONCE
    if word in {"s", "session"}:
        return Answer.ALLOW_SESSION
    return Answer.DENY


def render_prompt(request: ApprovalRequest, timeout: float) -> str:
    """The text shown on the terminal."""
    what = "outgoing call" if request.direction == "call" else "tool result"
    lines = [
        "",
        "--- Airlock needs your approval ---",
        f"Server  {printable(request.server, 80)}",
        f"Tool    {printable(request.tool, 80)} ({what})",
        f"Rule    {printable(request.rule, 80)}",
    ]
    for index, reason in enumerate(request.reasons or ("(no reason given)",)):
        head = "Why     " if index == 0 else "        "
        lines.append(head + printable(reason, _MAX_REASON))
    if request.arguments:
        lines.append(f"Args    {printable(request.arguments, _MAX_ARGS)}")
    lines.append(f"Allow?  [y] once  [s] this session  [n] deny   (denies in {timeout:g} s): ")
    return "\r\n".join(lines)


def _open_dev_tty() -> int:
    return os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)


class TerminalApprover:
    """Approver that prompts on the controlling terminal.

    Args:
        timeout: Seconds to wait for an answer before denying.
        lock_path: A file used to keep prompts from several ``airlock wrap``
            processes (one per server, same terminal) from interleaving.
        open_terminal: Returns a read/write file descriptor for the terminal
            (POSIX). Tests pass the slave end of a pty; raising ``OSError``
            means "no terminal".
    """

    def __init__(
        self,
        timeout: float = 30.0,
        *,
        lock_path: Path | None = None,
        open_terminal: OpenTerminal | None = None,
    ) -> None:
        self.timeout = timeout
        self.lock_path = lock_path
        self._open_terminal = open_terminal or _open_dev_tty
        self._owns_fd = open_terminal is None
        self._lock = asyncio.Lock()

    async def request(self, request: ApprovalRequest) -> ApprovalOutcome:
        deadline = time.monotonic() + self.timeout
        prompt = render_prompt(request, self.timeout)
        # One prompt at a time per process; the file lock covers other processes.
        async with self._lock:
            if sys.platform == "win32":
                return await self._run(self._ask_windows, prompt, deadline)
            return await self._run(self._ask_posix, prompt, deadline)

    async def _run(
        self, ask: Callable[[str, float, int], ApprovalOutcome], prompt: str, deadline: float
    ) -> ApprovalOutcome:
        stop_read, stop_write = os.pipe()
        try:
            outcome = await asyncio.to_thread(ask, prompt, deadline, stop_read)
        except BaseException:
            # Cancelled (shutdown): wake the waiting thread so it does not sit until
            # the timeout, and close its end once it has had time to notice.
            with contextlib.suppress(OSError):
                os.write(stop_write, b"x")
            _close_quietly(stop_write)
            asyncio.get_running_loop().call_later(1.0, _close_quietly, stop_read)
            raise
        _close_quietly(stop_write)
        _close_quietly(stop_read)
        return outcome

    def _outcome(self, answer: Answer) -> ApprovalOutcome:
        details = {
            Answer.ALLOW_ONCE: "approved once at the terminal",
            Answer.ALLOW_SESSION: "approved for this session at the terminal",
            Answer.DENY: "denied at the terminal",
            Answer.TIMEOUT: f"no answer at the terminal within {self.timeout:g} s; denied",
            Answer.UNAVAILABLE: (
                "approval required but no terminal is available to ask; treated as deny"
            ),
        }
        return ApprovalOutcome(answer, details[answer])

    # -- POSIX ------------------------------------------------------------------

    if sys.platform != "win32":

        def _ask_posix(self, prompt: str, deadline: float, stop_fd: int) -> ApprovalOutcome:
            import select
            import termios

            try:
                fd = self._open_terminal()
            except OSError:
                return self._outcome(Answer.UNAVAILABLE)
            try:
                with self._file_lock(deadline, stop_fd) as locked:
                    if not locked:
                        return self._outcome(Answer.TIMEOUT)
                    try:
                        canonical = bool(termios.tcgetattr(fd)[3] & termios.ICANON)
                    except termios.error:
                        canonical = True
                    with contextlib.suppress(termios.error):
                        termios.tcflush(fd, termios.TCIFLUSH)  # drop stale keystrokes
                    os.write(fd, prompt.encode("utf-8", errors="replace"))
                    buffer = b""
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            break
                        ready, _, _ = select.select([fd, stop_fd], [], [], remaining)
                        if stop_fd in ready:
                            break
                        if fd not in ready:
                            continue
                        chunk = os.read(fd, 1024)
                        if not chunk:  # terminal hung up
                            return self._outcome(Answer.UNAVAILABLE)
                        buffer += chunk
                        if b"\n" in buffer or b"\r" in buffer:
                            line = buffer.replace(b"\r", b"\n").split(b"\n", 1)[0]
                            return self._answered(fd, line)
                        if not canonical and buffer.strip():
                            # Raw mode (a full-screen client owns the tty): one key decides.
                            return self._answered(fd, buffer.strip()[:1])
                    os.write(fd, f"\r\n(no answer in {self.timeout:g} s: denied)\r\n".encode())
                    with contextlib.suppress(termios.error):
                        termios.tcflush(fd, termios.TCIFLUSH)
                    return self._outcome(Answer.TIMEOUT)
            except OSError:
                return self._outcome(Answer.UNAVAILABLE)
            finally:
                if self._owns_fd:
                    _close_quietly(fd)

        def _answered(self, fd: int, raw: bytes) -> ApprovalOutcome:
            answer = parse_answer(raw.decode("utf-8", errors="replace"))
            word = {
                Answer.ALLOW_ONCE: "allowed once",
                Answer.ALLOW_SESSION: "allowed for this session",
            }.get(answer, "denied")
            os.write(fd, f"\r\nAirlock: {word}.\r\n".encode())
            return self._outcome(answer)

        @contextlib.contextmanager
        def _file_lock(self, deadline: float, stop_fd: int) -> Iterator[bool]:
            if self.lock_path is None:
                yield True
                return
            import fcntl
            import select

            try:
                self.lock_path.parent.mkdir(parents=True, exist_ok=True)
                lock_fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
            except OSError:
                yield True  # cannot lock: prompting anyway beats denying
                return
            try:
                while True:
                    try:
                        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            yield False
                            return
                        ready, _, _ = select.select(
                            [stop_fd], [], [], min(_POLL_SECONDS, remaining)
                        )
                        if ready:
                            yield False
                            return
                try:
                    yield True
                finally:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)

    # -- Windows ----------------------------------------------------------------

    if sys.platform == "win32":

        def _ask_windows(self, prompt: str, deadline: float, stop_fd: int) -> ApprovalOutcome:
            import msvcrt

            del stop_fd  # select() does not work on pipes on Windows; poll the deadline only
            try:
                console = open("CONOUT$", "w", encoding="utf-8", errors="replace")
            except OSError:
                return self._outcome(Answer.UNAVAILABLE)
            with console:
                console.write(prompt)
                console.flush()
                while msvcrt.kbhit():  # drop stale keystrokes
                    msvcrt.getwch()
                typed = ""
                while time.monotonic() < deadline:
                    if not msvcrt.kbhit():
                        time.sleep(_POLL_SECONDS)
                        continue
                    char = msvcrt.getwch()
                    if char in "\r\n":
                        console.write("\n")
                        console.flush()
                        return self._outcome(parse_answer(typed))
                    if char == "\x08":
                        typed = typed[:-1]
                    else:
                        typed += char
                    console.write(char)
                    console.flush()
                console.write(f"\n(no answer in {self.timeout:g} s: denied)\n")
                return self._outcome(Answer.TIMEOUT)


def _close_quietly(fd: int) -> None:
    with contextlib.suppress(OSError):
        os.close(fd)


__all__ = ["TerminalApprover", "parse_answer", "printable", "render_prompt"]
