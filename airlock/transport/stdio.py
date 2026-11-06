"""Standard I/O (stdio) MCP proxy transport."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import sys
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from airlock.engine import Engine
from airlock.models import Decision, ToolCall, ToolResult, Verdict

_MAX_LINE_BYTES = 1_048_576
_MAX_PENDING_REQUESTS = 4096


def get_server_id(command: Sequence[str], name: str | None = None) -> str:
    """Return explicit server name or a stable short SHA256 hash of the command."""
    if name and name.strip():
        return name.strip()
    cmd_str = " ".join(command)
    return hashlib.sha256(cmd_str.encode("utf-8")).hexdigest()[:12]


def _log_warning(message: str) -> None:
    """Write diagnostic warning to stderr without polluting protocol stdout."""
    sys.stderr.write(f"[airlock] {' '.join(message.split())[:500]}\n")
    sys.stderr.flush()


def _default_stdout_write(line: str) -> None:
    """Write protocol line to standard output and flush."""
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def _write_error(
    write_stdout: Callable[[str], None],
    request_id: str | int | None,
    code: int,
    message: str,
) -> None:
    """Write a bounded JSON-RPC error response."""
    write_stdout(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": code, "message": message},
            }
        )
    )


@dataclass
class _ClientState:
    """What the proxy learned about the MCP client (from its ``initialize`` request)."""

    name: str | None = None


def _note_client(engine: Engine, server_id: str, client: _ClientState, params: Any) -> None:
    info = params.get("clientInfo") if isinstance(params, dict) else None
    name = info.get("name") if isinstance(info, dict) else None
    if not isinstance(name, str) or not name.strip():
        return
    client.name = " ".join(name.split())[:100]
    try:
        engine.note_client(server_id, client.name)
    except Exception as exc:
        _log_warning(f"Could not record the client's servers: {type(exc).__name__}: {exc}")


async def _warn_trifecta(engine: Engine, client: _ClientState) -> None:
    """Warn on stderr when the client's servers together form the lethal trifecta."""
    if client.name is None:
        return
    try:
        found = await engine.report_trifecta(client.name)
    except Exception as exc:
        _log_warning(f"Trifecta check failed: {type(exc).__name__}: {exc}")
        return
    if found is not None:
        sys.stderr.write(f"[airlock] WARNING: {found.message()}\n")
        sys.stderr.flush()


def _blocked_result(reasons: Sequence[str]) -> dict[str, Any]:
    reasons_text = "; ".join(reasons) if reasons else "Blocked by policy"
    return {
        "content": [{"type": "text", "text": f"Blocked by Airlock: {reasons_text}"}],
        "isError": True,
    }


async def _approve_call(
    engine: Engine,
    call: ToolCall,
    decision: Decision,
    line: str,
    child_stdin: asyncio.StreamWriter,
    write_stdout: Callable[[str], None],
    pending_requests: dict[Any, dict[str, Any]],
) -> None:
    """Ask a human about a call; forward it to the server only if they allow it."""
    msg_id = call.request_id if call.request_id != "no-id" else None
    try:
        final = await engine.resolve_ask(call, decision)
    except Exception as exc:
        _log_warning(f"Approval failed: {type(exc).__name__}: {exc}")
        final = Decision(verdict=Verdict.DENY, reasons=["approval failed; treated as deny"])
    if final.verdict == Verdict.ALLOW:
        try:
            child_stdin.write((line + "\n").encode("utf-8"))
            await child_stdin.drain()
            return
        except Exception as exc:
            _log_warning(f"Could not forward approved call: {exc}")
            final = Decision(verdict=Verdict.DENY, reasons=["the server is no longer reachable"])
    pending_requests.pop(msg_id, None)
    write_stdout(
        json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": _blocked_result(final.reasons)})
    )


async def _approve_result(
    engine: Engine,
    result: ToolResult,
    decision: Decision,
    msg: dict[str, Any],
    write_stdout: Callable[[str], None],
) -> None:
    """Ask a human whether a tool result may reach the client."""
    try:
        final = await engine.resolve_ask(result, decision)
    except Exception as exc:
        _log_warning(f"Approval failed: {type(exc).__name__}: {exc}")
        final = Decision(verdict=Verdict.DENY, reasons=["approval failed; treated as deny"])
    if final.verdict != Verdict.ALLOW:
        msg["result"] = _blocked_result(final.reasons)
    write_stdout(json.dumps(msg))


def _valid_request_id(value: object) -> bool:
    return value is None or (isinstance(value, (str, int)) and not isinstance(value, bool))


def _valid_jsonrpc_object(value: object) -> bool:
    return isinstance(value, dict) and value.get("jsonrpc") == "2.0"


def _track_request(
    pending_requests: dict[Any, dict[str, Any]],
    request_id: object,
    details: dict[str, Any],
) -> bool:
    if not _valid_request_id(request_id) or request_id is None:
        return False
    if request_id in pending_requests or len(pending_requests) >= _MAX_PENDING_REQUESTS:
        return False
    pending_requests[request_id] = details
    return True


async def _client_to_server_relay(
    stdin_reader: asyncio.StreamReader | None,
    child_stdin: asyncio.StreamWriter,
    write_stdout: Callable[[str], None],
    engine: Engine,
    session_id: str,
    server_id: str,
    pending_requests: dict[Any, dict[str, Any]],
    stop_event: asyncio.Event,
    client: _ClientState | None = None,
) -> None:
    """Read lines from client stdin, apply outbound checks, and forward to server.

    A call that needs approval waits in its own task, so other requests (and
    cancellations, pings) keep flowing while the human decides.
    """
    approvals: set[asyncio.Task[None]] = set()
    try:
        await _client_loop(
            stdin_reader,
            child_stdin,
            write_stdout,
            engine,
            session_id,
            server_id,
            pending_requests,
            stop_event,
            approvals,
            client if client is not None else _ClientState(),
        )
    finally:
        for task in approvals:
            task.cancel()


async def _client_loop(
    stdin_reader: asyncio.StreamReader | None,
    child_stdin: asyncio.StreamWriter,
    write_stdout: Callable[[str], None],
    engine: Engine,
    session_id: str,
    server_id: str,
    pending_requests: dict[Any, dict[str, Any]],
    stop_event: asyncio.Event,
    approvals: set[asyncio.Task[None]],
    client: _ClientState,
) -> None:
    while not stop_event.is_set():
        if stdin_reader is not None:
            raw_bytes = await stdin_reader.readline()
            if not raw_bytes:
                break
            line = raw_bytes.decode("utf-8", errors="replace").rstrip("\r\n")
        else:
            raw_line = await asyncio.to_thread(sys.stdin.readline)
            if not raw_line:
                break
            line = raw_line.rstrip("\r\n")

        if len(line.encode("utf-8", errors="replace")) > _MAX_LINE_BYTES:
            _log_warning("Client message exceeded the maximum size and was dropped")
            _write_error(write_stdout, None, -32600, "Request is too large")
            continue
        if not line.strip():
            continue

        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            _log_warning("Client line is not valid JSON and was dropped")
            _write_error(write_stdout, None, -32700, "Parse error")
            continue

        if not _valid_jsonrpc_object(msg):
            _log_warning("Client message is not a JSON-RPC 2.0 object and was dropped")
            _write_error(write_stdout, None, -32600, "Invalid Request")
            continue

        method = msg.get("method")
        msg_id = msg.get("id")
        if not _valid_request_id(msg_id):
            _log_warning("Client request has an invalid JSON-RPC id and was dropped")
            _write_error(write_stdout, None, -32600, "Invalid Request")
            continue

        if method == "initialize":
            _note_client(engine, server_id, client, msg.get("params"))

        if method == "tools/call":
            params = msg.get("params")
            if not isinstance(params, dict):
                _write_error(write_stdout, msg_id, -32602, "Invalid params")
                continue
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
            if not isinstance(tool_name, str) or not isinstance(arguments, dict):
                _write_error(write_stdout, msg_id, -32602, "Invalid params")
                continue

            if msg_id is not None:
                if not _track_request(
                    pending_requests,
                    msg_id,
                    {
                        "method": "tools/call",
                        "tool_name": tool_name,
                        "arguments": arguments,
                    },
                ):
                    _write_error(write_stdout, msg_id, -32000, "Too many pending requests")
                    continue

            call = ToolCall(
                session_id=session_id,
                server_id=server_id,
                tool_name=tool_name,
                arguments=arguments,
                request_id=msg_id if msg_id is not None else "no-id",
            )
            decision = await engine.on_tool_call(call)

            if decision.verdict == Verdict.DENY:
                # Do not forward; answer client directly with isError=True
                response = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": _blocked_result(decision.reasons),
                }
                write_stdout(json.dumps(response))
                pending_requests.pop(msg_id, None)
                continue

            elif decision.verdict == Verdict.ASK:
                if decision.modified_payload is not None:
                    params["arguments"] = decision.modified_payload
                    msg["params"] = params
                    line = json.dumps(msg)
                task = asyncio.create_task(
                    _approve_call(
                        engine, call, decision, line, child_stdin, write_stdout, pending_requests
                    )
                )
                approvals.add(task)
                task.add_done_callback(approvals.discard)
                continue

            elif decision.verdict == Verdict.REDACT:
                # Outbound redaction / payload modification
                if decision.modified_payload is not None:
                    if isinstance(decision.modified_payload, dict):
                        params["arguments"] = decision.modified_payload
                    msg["params"] = params
                line = json.dumps(msg)

        elif method == "tools/list":
            if msg_id is not None:
                if not _track_request(pending_requests, msg_id, {"method": "tools/list"}):
                    _write_error(write_stdout, msg_id, -32000, "Too many pending requests")
                    continue

        else:
            if msg_id is not None and method:
                if not _track_request(pending_requests, msg_id, {"method": method}):
                    _write_error(write_stdout, msg_id, -32000, "Too many pending requests")
                    continue

        child_stdin.write((line + "\n").encode("utf-8"))
        await child_stdin.drain()


async def _server_to_client_relay(
    child_stdout: asyncio.StreamReader,
    child_stdin: asyncio.StreamWriter,
    write_stdout: Callable[[str], None],
    engine: Engine,
    session_id: str,
    server_id: str,
    pending_requests: dict[Any, dict[str, Any]],
    stop_event: asyncio.Event,
    client: _ClientState | None = None,
) -> None:
    """Read lines from server stdout, apply inbound checks, and forward to client."""
    client = client if client is not None else _ClientState()
    internal_futures: dict[str, asyncio.Future[list[dict[str, Any]]]] = {}
    bg_tasks: set[asyncio.Task[None]] = set()

    while not stop_event.is_set():
        raw_bytes = await child_stdout.readline()
        if not raw_bytes:
            break

        line = raw_bytes.decode("utf-8", errors="replace").rstrip("\r\n")
        if len(raw_bytes) > _MAX_LINE_BYTES:
            _log_warning("Server message exceeded the maximum size and was dropped")
            continue
        if not line.strip():
            continue

        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            _log_warning("Server line is not valid JSON and was dropped")
            continue

        if not _valid_jsonrpc_object(msg):
            _log_warning("Server message is not a JSON-RPC 2.0 object and was dropped")
            continue

        msg_id = msg.get("id")
        method = msg.get("method")

        # Check if this message is a response to an internal Airlock tools/list request
        if msg_id is not None and str(msg_id) in internal_futures:
            fut = internal_futures.pop(str(msg_id))
            if not fut.done():
                result_obj = msg.get("result", {})
                raw_tools = result_obj.get("tools", []) if isinstance(result_obj, dict) else []
                fut.set_result(raw_tools)
            # NEVER forward internal responses to client stdout
            continue

        # Hook 4: notifications/tools/list_changed from the server
        if method == "notifications/tools/list_changed":
            _log_warning("notifications/tools/list_changed received from server")

            # Send internal tools/list request to server, update registry, then forward
            loop = asyncio.get_running_loop()
            internal_id = f"__airlock_internal_list__{uuid.uuid4()}"
            fut = loop.create_future()
            internal_futures[internal_id] = fut

            # Send internal request to server child
            req_msg = {
                "jsonrpc": "2.0",
                "id": internal_id,
                "method": "tools/list",
                "params": {},
            }
            child_stdin.write((json.dumps(req_msg) + "\n").encode("utf-8"))
            await child_stdin.drain()

            async def _update_and_forward(
                notification_line: str,
                future: asyncio.Future[list[dict[str, Any]]],
            ) -> None:
                try:
                    tools_data = await asyncio.wait_for(future, timeout=5.0)
                    await engine.on_tools_listed(server_id, tools_data)
                    await _warn_trifecta(engine, client)
                except Exception as exc:
                    _log_warning(f"Failed to refresh registry on list_changed: {exc}")
                write_stdout(notification_line)

            task = asyncio.create_task(_update_and_forward(line, fut))
            bg_tasks.add(task)
            task.add_done_callback(bg_tasks.discard)
            continue

        # Match response to pending requests
        if msg_id is not None and msg_id in pending_requests:
            req_info = pending_requests.pop(msg_id)
            req_method = req_info.get("method")

            # Hook 2: server response to tools/call
            if req_method == "tools/call" and "result" in msg:
                result_obj = msg["result"]
                if isinstance(result_obj, dict):
                    content = result_obj.get("content", [])
                    is_error = bool(result_obj.get("isError", False))
                    structured_content = result_obj.get("structuredContent")
                    if not isinstance(content, list) or not all(
                        isinstance(item, dict) for item in content
                    ):
                        _log_warning("Server returned malformed tool-result content")
                        msg["result"] = {
                            "content": [
                                {
                                    "type": "text",
                                    "text": "Blocked by Airlock: malformed tool result",
                                }
                            ],
                            "isError": True,
                        }
                        line = json.dumps(msg)
                        write_stdout(line)
                        continue
                    if structured_content is not None and not isinstance(structured_content, dict):
                        _log_warning("Server returned malformed structured tool content")
                        msg["result"] = {
                            "content": [
                                {
                                    "type": "text",
                                    "text": "Blocked by Airlock: malformed tool result",
                                }
                            ],
                            "isError": True,
                        }
                        line = json.dumps(msg)
                        write_stdout(line)
                        continue

                    tool_result = ToolResult(
                        session_id=session_id,
                        server_id=server_id,
                        tool_name=req_info.get("tool_name", ""),
                        request_id=msg_id,
                        content=content if isinstance(content, list) else [],
                        is_error=is_error,
                        structured_content=(
                            structured_content if isinstance(structured_content, dict) else None
                        ),
                    )
                    decision = await engine.on_tool_result(tool_result)

                    if decision.verdict == Verdict.DENY:
                        msg["result"] = _blocked_result(decision.reasons)
                        line = json.dumps(msg)

                    elif decision.verdict == Verdict.ASK:
                        task = asyncio.create_task(
                            _approve_result(engine, tool_result, decision, msg, write_stdout)
                        )
                        bg_tasks.add(task)
                        task.add_done_callback(bg_tasks.discard)
                        continue

                    elif decision.verdict == Verdict.REDACT:
                        if decision.modified_payload is not None:
                            if (
                                isinstance(decision.modified_payload, dict)
                                and "content" in decision.modified_payload
                            ):
                                msg["result"] = decision.modified_payload
                            elif isinstance(decision.modified_payload, list):
                                msg["result"]["content"] = decision.modified_payload
                            else:
                                msg["result"]["content"] = [
                                    {
                                        "type": "text",
                                        "text": str(decision.modified_payload),
                                    }
                                ]
                        line = json.dumps(msg)

            # Hook 3: server response to tools/list
            elif req_method == "tools/list" and "result" in msg:
                result_obj = msg["result"]
                if isinstance(result_obj, dict) and "tools" in result_obj:
                    raw_tools = result_obj["tools"]
                    if isinstance(raw_tools, list):
                        filtered_tools = await engine.on_tools_listed(server_id, raw_tools)
                        await _warn_trifecta(engine, client)
                        result_obj["tools"] = [
                            t.model_dump(
                                by_alias=True,
                                exclude={"server_id"},
                                exclude_none=True,
                            )
                            for t in filtered_tools
                        ]
                        msg["result"] = result_obj
                        line = json.dumps(msg)

        write_stdout(line)


async def run_stdio_proxy(
    command: Sequence[str],
    name: str | None = None,
    engine: Engine | None = None,
    stdin_reader: asyncio.StreamReader | None = None,
    stdout_writer: Callable[[str], None] | None = None,
) -> int:
    """Run bidirectional stdio proxy between MCP client and child server."""
    if not command:
        raise ValueError("No command provided to wrap")

    active_engine = engine if engine is not None else Engine()
    server_id = get_server_id(command, name)
    session_id = str(uuid.uuid4())
    write_stdout = stdout_writer or _default_stdout_write

    # Spawn child server process
    child = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=sys.stderr,
        env=os.environ,
    )

    if child.stdin is None or child.stdout is None:
        raise RuntimeError("Failed to establish stdio pipes with child process")

    # Connect to client stdin if not supplied
    loop = asyncio.get_running_loop()
    if stdin_reader is None:
        try:
            reader = asyncio.StreamReader()
            protocol = asyncio.StreamReaderProtocol(reader)
            await loop.connect_read_pipe(lambda: protocol, sys.stdin)
            active_stdin_reader: asyncio.StreamReader | None = reader
        except Exception:
            active_stdin_reader = None
    else:
        active_stdin_reader = stdin_reader

    pending_requests: dict[Any, dict[str, Any]] = {}
    stop_event = asyncio.Event()
    client = _ClientState()

    # Signal handling
    def _handle_signal(sig: int) -> None:
        _log_warning(f"Received signal {sig}, terminating child process...")
        try:
            child.send_signal(sig)
        except Exception:
            pass
        stop_event.set()

    def _make_signal_handler(sig: signal.Signals) -> Callable[[], None]:
        return lambda: _handle_signal(sig)

    registered_signals: list[signal.Signals] = []
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _make_signal_handler(sig))
            registered_signals.append(sig)
        except (NotImplementedError, AttributeError, RuntimeError, ValueError):
            pass

    client_task = asyncio.create_task(
        _client_to_server_relay(
            stdin_reader=active_stdin_reader,
            child_stdin=child.stdin,
            write_stdout=write_stdout,
            engine=active_engine,
            session_id=session_id,
            server_id=server_id,
            pending_requests=pending_requests,
            stop_event=stop_event,
            client=client,
        )
    )

    server_task = asyncio.create_task(
        _server_to_client_relay(
            child_stdout=child.stdout,
            child_stdin=child.stdin,
            write_stdout=write_stdout,
            engine=active_engine,
            session_id=session_id,
            server_id=server_id,
            pending_requests=pending_requests,
            stop_event=stop_event,
            client=client,
        )
    )

    try:
        # Wait until either side closes
        _done, pending = await asyncio.wait(
            [client_task, server_task],
            return_when=asyncio.FIRST_COMPLETED,
        )
        stop_event.set()

        for t in pending:
            t.cancel()

        # Close child stdin
        try:
            if not child.stdin.is_closing():
                child.stdin.close()
                await child.stdin.wait_closed()
        except Exception:
            pass

        # Wait for child process exit
        try:
            await asyncio.wait_for(child.wait(), timeout=3.0)
        except TimeoutError:
            try:
                child.kill()
                await child.wait()
            except Exception:
                pass

    finally:
        for sig in registered_signals:
            try:
                loop.remove_signal_handler(sig)
            except Exception:
                pass
        try:
            await active_engine.close()
        except Exception:
            pass

    return child.returncode if child.returncode is not None else 0


__all__ = [
    "get_server_id",
    "run_stdio_proxy",
]
