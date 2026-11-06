"""Streamable HTTP MCP proxy (``airlock serve``).

Written against the MCP 2026-07-28 Streamable HTTP binding and the SDK it ships
with (``mcp`` 2.3, ``httpx2``):

- Every JSON-RPC message is its own POST; a request is answered with one JSON
  object or a request-scoped SSE stream (notifications, then the response).
- 2026-07-28 removed protocol sessions and the GET stream. Earlier revisions
  (2025-03-26 to 2025-11-25) used ``Mcp-Session-Id`` and a GET stream, so the
  proxy forwards GET and DELETE, the session header and ``Last-Event-ID``
  untouched and works with servers and clients of either era.
- Selected body fields are mirrored into headers (``Mcp-Method``, ``Mcp-Name``,
  ``Mcp-Param-*``). Airlock decides on the body and forwards the body it
  parsed, re-serialised, so the upstream sees exactly what was checked; when
  it redacts arguments it rewrites the ``Mcp-Param-*`` headers to match.

Only ``tools/list`` and ``tools/call`` responses are parsed. Everything else is
streamed through as it arrives; in an intercepted SSE stream only the event
holding the response waits for inspection.
"""

from __future__ import annotations

import base64
import json
import sys
import uuid
from collections.abc import AsyncIterator, Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx2
from starlette.applications import Starlette
from starlette.requests import ClientDisconnect, Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from airlock.engine import Engine
from airlock.models import Decision, ToolCall, ToolResult, Verdict
from airlock.transport.sse import SSEParser, encode_event

MAX_BODY_BYTES = 1_048_576
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
        "accept-encoding",
    }
)
_RESPONSE_DROP = frozenset(
    {"connection", "keep-alive", "transfer-encoding", "content-length", "trailer", "upgrade"}
)
_LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})
_META_PROTOCOL = "io.modelcontextprotocol/protocolVersion"
_META_CLIENT = "io.modelcontextprotocol/clientInfo"


def _warn(message: str) -> None:
    sys.stderr.write(f"[airlock serve] {' '.join(message.split())[:500]}\n")
    sys.stderr.flush()


def _jsonrpc_error(code: int, message: str, request_id: Any = None) -> dict[str, Any]:
    error: dict[str, Any] = {"jsonrpc": "2.0", "error": {"code": code, "message": message}}
    if request_id is not None:
        error["id"] = request_id
    return error


def _blocked_result(reasons: list[str], modern: bool) -> dict[str, Any]:
    text = "; ".join(reasons) if reasons else "Blocked by policy"
    result: dict[str, Any] = {
        "content": [{"type": "text", "text": f"Blocked by Airlock: {text}"}],
        "isError": True,
    }
    if modern:
        result["resultType"] = "complete"
    return result


# -- Mirrored headers ---------------------------------------------------------


def encode_header_value(value: str | int | bool) -> str:
    """Encode a value for an ``Mcp-Param-*`` / ``Mcp-Name`` header (spec "Value Encoding")."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    plain = (
        all(char == "\t" or 0x20 <= ord(char) <= 0x7E for char in value)
        and value == value.strip()
        and not (value.startswith("=?base64?") and value.endswith("?="))
    )
    if plain:
        return value
    return "=?base64?" + base64.b64encode(value.encode("utf-8")).decode("ascii") + "?="


def mirrored_params(schema: Mapping[str, Any]) -> list[tuple[str, list[str]]]:
    """``(header name, property path)`` for each ``x-mcp-header`` reachable via ``properties``."""
    found: list[tuple[str, list[str]]] = []

    def walk(node: Mapping[str, Any], path: list[str]) -> None:
        properties = node.get("properties")
        if not isinstance(properties, Mapping):
            return
        for key, child in properties.items():
            if not isinstance(child, Mapping):
                continue
            name = child.get("x-mcp-header")
            if isinstance(name, str) and name:
                found.append((name, [*path, str(key)]))
            walk(child, [*path, str(key)])

    walk(schema, [])
    return found


def remirror_headers(
    headers: dict[str, str], schema: Mapping[str, Any], arguments: Mapping[str, Any]
) -> None:
    """Make ``Mcp-Param-*`` headers match (redacted) arguments again."""
    for name, path in mirrored_params(schema):
        header = f"mcp-param-{name}".lower()
        for existing in [key for key in headers if key.lower() == header]:
            del headers[existing]
        value: Any = arguments
        for part in path:
            value = value.get(part) if isinstance(value, Mapping) else None
        if isinstance(value, (str, int, bool)) and not isinstance(value, float):
            headers[f"Mcp-Param-{name}"] = encode_header_value(value)


# -- Proxy --------------------------------------------------------------------


class HttpProxy:
    """One local MCP endpoint in front of one upstream Streamable HTTP server."""

    def __init__(
        self,
        engine: Engine,
        upstream: str,
        server_id: str,
        *,
        client: httpx2.AsyncClient | None = None,
        allowed_origins: tuple[str, ...] = (),
        max_body_bytes: int = MAX_BODY_BYTES,
    ) -> None:
        self.engine = engine
        self.upstream = upstream
        self.server_id = server_id
        self.allowed_origins = tuple(origin.rstrip("/").lower() for origin in allowed_origins)
        self.max_body_bytes = max_body_bytes
        self.session_id = str(uuid.uuid4())
        self._client = client or httpx2.AsyncClient(
            timeout=httpx2.Timeout(30.0, read=None), follow_redirects=False
        )
        self._clients_noted: set[str] = set()
        parts = urlsplit(upstream)
        self._upstream_path = parts.path or "/"
        self._upstream_origin = (parts.scheme, parts.netloc)

    def app(self) -> Starlette:
        methods = ["GET", "POST", "DELETE", "PUT", "PATCH", "OPTIONS", "HEAD"]
        return Starlette(routes=[Route("/{path:path}", self.handle, methods=methods)])

    async def aclose(self) -> None:
        await self._client.aclose()

    # -- request plumbing --

    def _target(self, request: Request) -> str:
        path = request.url.path
        if path.rstrip("/") == self._upstream_path.rstrip("/"):
            target = self.upstream
        else:
            scheme, netloc = self._upstream_origin
            target = urlunsplit((scheme, netloc, path, "", ""))
        query = request.url.query
        if query:
            target += ("&" if "?" in target else "?") + query
        return target

    def _origin_allowed(self, origin: str | None) -> bool:
        if origin is None or origin == "null":
            return origin is None
        if origin.rstrip("/").lower() in self.allowed_origins:
            return True
        return (urlsplit(origin).hostname or "") in _LOCAL_HOSTS

    @staticmethod
    def _forward_headers(request: Request) -> dict[str, str]:
        headers = {
            key: value for key, value in request.headers.items() if key.lower() not in _HOP_BY_HOP
        }
        headers["accept-encoding"] = "identity"  # so streamed bytes need no re-encoding
        return headers

    @staticmethod
    def _response_headers(response: httpx2.Response) -> dict[str, str]:
        return {
            key: value
            for key, value in response.headers.items()
            if key.lower() not in _RESPONSE_DROP
        }

    def _session(self, request: Request) -> str:
        return request.headers.get("mcp-session-id") or self.session_id

    def _note_client(self, msg: Mapping[str, Any]) -> None:
        params = msg.get("params")
        if not isinstance(params, Mapping):
            return
        info: Any = None
        meta = params.get("_meta")
        if isinstance(meta, Mapping):
            info = meta.get(_META_CLIENT)
        if info is None and msg.get("method") == "initialize":
            info = params.get("clientInfo")
        name = info.get("name") if isinstance(info, Mapping) else None
        if not isinstance(name, str) or not name.strip():
            return
        name = " ".join(name.split())[:100]
        if name in self._clients_noted:
            return
        self._clients_noted.add(name)
        try:
            self.engine.note_client(self.server_id, name)
        except Exception as exc:
            _warn(f"Could not record the client's servers: {type(exc).__name__}: {exc}")

    async def _read_body(self, request: Request) -> bytes | None:
        chunks: list[bytes] = []
        size = 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > self.max_body_bytes:
                return None
            chunks.append(chunk)
        return b"".join(chunks)

    async def _send(
        self, request: Request, target: str, headers: dict[str, str], body: bytes | None
    ) -> httpx2.Response:
        upstream_request = self._client.build_request(
            request.method, target, headers=headers, content=body
        )
        return await self._client.send(upstream_request, stream=True)

    # -- handler --

    async def handle(self, request: Request) -> Response:
        if not self._origin_allowed(request.headers.get("origin")):
            return JSONResponse(_jsonrpc_error(-32600, "Forbidden origin"), status_code=403)
        target = self._target(request)
        headers = self._forward_headers(request)
        if request.method != "POST":
            return await self._passthrough(request, target, headers, None)

        try:
            body = await self._read_body(request)
        except ClientDisconnect:
            return Response(status_code=499)
        if body is None:
            return JSONResponse(_jsonrpc_error(-32600, "Request is too large"), status_code=413)
        try:
            msg = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return JSONResponse(_jsonrpc_error(-32700, "Parse error"), status_code=400)
        if not isinstance(msg, dict):
            # JSON-RPC batches were removed in 2025-06-18; refusing them keeps
            # every call inspectable.
            return JSONResponse(
                _jsonrpc_error(-32600, "Batches are not supported by Airlock"), status_code=400
            )
        self._note_client(msg)
        method = msg.get("method")
        if method == "tools/call" and "id" in msg:
            return await self._tools_call(request, target, headers, msg)
        if method == "tools/list" and "id" in msg:
            canonical = json.dumps(msg).encode("utf-8")
            return await self._intercept(request, target, headers, canonical, msg, "list")
        return await self._passthrough(request, target, headers, body)

    async def _passthrough(
        self, request: Request, target: str, headers: dict[str, str], body: bytes | None
    ) -> Response:
        try:
            upstream = await self._send(request, target, headers, body)
        except httpx2.HTTPError as exc:
            return self._bad_gateway(exc)

        async def stream() -> AsyncIterator[bytes]:
            try:
                async for chunk in upstream.aiter_raw():
                    yield chunk
            finally:
                await upstream.aclose()

        return StreamingResponse(
            stream(), status_code=upstream.status_code, headers=self._response_headers(upstream)
        )

    @staticmethod
    def _bad_gateway(exc: Exception) -> Response:
        _warn(f"Upstream request failed: {type(exc).__name__}: {exc}")
        return JSONResponse(
            _jsonrpc_error(
                -32603, f"Airlock could not reach the upstream server ({type(exc).__name__})"
            ),
            status_code=502,
        )

    # -- tools/call --

    async def _tools_call(
        self, request: Request, target: str, headers: dict[str, str], msg: dict[str, Any]
    ) -> Response:
        params = msg.get("params")
        request_id = msg.get("id")
        modern = (
            isinstance(params, dict)
            and isinstance(params.get("_meta"), dict)
            and (_META_PROTOCOL in params["_meta"])
        )
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            return JSONResponse(
                _jsonrpc_error(-32602, "Invalid params", request_id), status_code=400
            )
        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            return JSONResponse(
                _jsonrpc_error(-32602, "Invalid params", request_id), status_code=400
            )

        call = ToolCall(
            session_id=self._session(request),
            server_id=self.server_id,
            tool_name=params["name"],
            arguments=arguments,
            request_id=request_id if isinstance(request_id, (str, int)) else "invalid",
        )
        decision = await self.engine.on_tool_call(call)
        if decision.verdict is Verdict.ASK:
            decision = await self.engine.resolve_ask(call, decision)
        if decision.verdict is Verdict.DENY:
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": _blocked_result(decision.reasons, modern),
                }
            )
        if decision.verdict is Verdict.REDACT and isinstance(decision.modified_payload, dict):
            params["arguments"] = decision.modified_payload
            schema = self._input_schema(call.tool_name)
            if schema:
                remirror_headers(headers, schema, decision.modified_payload)
        canonical = json.dumps(msg).encode("utf-8")
        context = {"tool": call.tool_name, "session": call.session_id, "modern": modern}
        return await self._intercept(request, target, headers, canonical, msg, "call", context)

    def _input_schema(self, tool_name: str) -> dict[str, Any] | None:
        record = self.engine.registry.get_tool(self.server_id, tool_name)
        if record is None:
            return None
        try:
            definition = json.loads(record["definition_json"])
        except (TypeError, ValueError):
            return None
        schema = definition.get("input_schema")
        return schema if isinstance(schema, dict) else None

    # -- response interception --

    async def _intercept(
        self,
        request: Request,
        target: str,
        headers: dict[str, str],
        body: bytes,
        msg: dict[str, Any],
        kind: str,
        context: dict[str, Any] | None = None,
    ) -> Response:
        try:
            upstream = await self._send(request, target, headers, body)
        except httpx2.HTTPError as exc:
            return self._bad_gateway(exc)
        request_id = msg.get("id")
        content_type = upstream.headers.get("content-type", "").lower()
        response_headers = self._response_headers(upstream)

        if content_type.startswith("application/json"):
            try:
                raw = await upstream.aread()
            finally:
                await upstream.aclose()
            try:
                reply = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError):
                return Response(raw, status_code=upstream.status_code, headers=response_headers)
            if isinstance(reply, dict) and reply.get("id") == request_id:
                reply = await self._inspect(reply, kind, context or {})
                raw = json.dumps(reply).encode("utf-8")
            return Response(raw, status_code=upstream.status_code, headers=response_headers)

        if content_type.startswith("text/event-stream"):

            async def events() -> AsyncIterator[bytes]:
                parser = SSEParser()
                try:
                    async for chunk in upstream.aiter_raw():
                        for event in parser.feed(chunk):
                            yield await self._event(event, request_id, kind, context or {})
                    tail = parser.close()
                    if tail is not None:
                        yield await self._event(tail, request_id, kind, context or {})
                finally:
                    await upstream.aclose()

            return StreamingResponse(
                events(), status_code=upstream.status_code, headers=response_headers
            )

        async def stream() -> AsyncIterator[bytes]:
            try:
                async for chunk in upstream.aiter_raw():
                    yield chunk
            finally:
                await upstream.aclose()

        return StreamingResponse(
            stream(), status_code=upstream.status_code, headers=response_headers
        )

    async def _event(
        self, event: Any, request_id: Any, kind: str, context: dict[str, Any]
    ) -> bytes:
        if event.data is None:
            return bytes(event.raw)
        try:
            payload = json.loads(event.data)
        except json.JSONDecodeError:
            return bytes(event.raw)
        if not (
            isinstance(payload, dict) and payload.get("id") == request_id and "result" in payload
        ):
            return bytes(event.raw)
        inspected = await self._inspect(payload, kind, context)
        if inspected is payload and not context.get("changed"):
            return bytes(event.raw)
        return encode_event(json.dumps(inspected), event=event.event, id=event.id)

    async def _inspect(
        self, reply: dict[str, Any], kind: str, context: dict[str, Any]
    ) -> dict[str, Any]:
        result = reply.get("result")
        if not isinstance(result, dict):
            return reply
        if kind == "list":
            return await self._inspect_list(reply, result)
        return await self._inspect_call(reply, result, context)

    async def _inspect_list(self, reply: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        tools = result.get("tools")
        if not isinstance(tools, list):
            return reply
        visible = await self.engine.on_tools_listed(self.server_id, tools)
        allowed = {tool.name for tool in visible}
        result = dict(result)
        result["tools"] = [
            tool for tool in tools if isinstance(tool, dict) and tool.get("name") in allowed
        ]
        for client in sorted(self._clients_noted):
            found = await self.engine.report_trifecta(client)
            if found is not None:
                _warn(f"WARNING: {found.message()}")
        return {**reply, "result": result}

    async def _inspect_call(
        self, reply: dict[str, Any], result: dict[str, Any], context: dict[str, Any]
    ) -> dict[str, Any]:
        result_type = result.get("resultType", "complete")
        if result_type != "complete":
            # e.g. input_required (multi round-trip): not a tool output yet.
            return reply
        content = result.get("content", [])
        structured = result.get("structuredContent")
        modern = bool(context.get("modern"))
        if (
            not isinstance(content, list)
            or not all(isinstance(item, dict) for item in content)
            or (structured is not None and not isinstance(structured, dict))
        ):
            context["changed"] = True
            return {**reply, "result": _blocked_result(["malformed tool result"], modern)}
        reply_id = reply.get("id")
        tool_result = ToolResult(
            session_id=str(context.get("session")),
            server_id=self.server_id,
            tool_name=str(context.get("tool")),
            request_id=reply_id if isinstance(reply_id, (str, int)) else "invalid",
            content=content,
            is_error=bool(result.get("isError", False)),
            structured_content=structured,
        )
        decision = await self.engine.on_tool_result(tool_result)
        if decision.verdict is Verdict.ASK:
            decision = await self.engine.resolve_ask(tool_result, decision)
        return self._apply_result(reply, result, decision, modern, context)

    @staticmethod
    def _apply_result(
        reply: dict[str, Any],
        result: dict[str, Any],
        decision: Decision,
        modern: bool,
        context: dict[str, Any],
    ) -> dict[str, Any]:
        if decision.verdict is Verdict.DENY:
            context["changed"] = True
            return {**reply, "result": _blocked_result(decision.reasons, modern)}
        if decision.verdict is Verdict.REDACT and isinstance(decision.modified_payload, dict):
            context["changed"] = True
            payload = decision.modified_payload
            updated = {key: value for key, value in result.items() if key != "structuredContent"}
            updated["content"] = payload.get("content", [])
            updated["isError"] = bool(payload.get("isError", result.get("isError", False)))
            if "structuredContent" in payload:
                updated["structuredContent"] = payload["structuredContent"]
            return {**reply, "result": updated}
        return reply


async def serve_proxies(
    proxies: list[tuple[HttpProxy, str, int]], log_level: str = "warning"
) -> None:
    """Run each proxy's app on its own ``host:port`` until interrupted."""
    import uvicorn

    servers = [
        uvicorn.Server(
            uvicorn.Config(proxy.app(), host=host, port=port, log_level=log_level, lifespan="off")
        )
        for proxy, host, port in proxies
    ]
    import asyncio

    try:
        await asyncio.gather(*(server.serve() for server in servers))
    finally:
        for proxy, _, _ in proxies:
            await proxy.aclose()


__all__ = [
    "HttpProxy",
    "encode_header_value",
    "mirrored_params",
    "remirror_headers",
    "serve_proxies",
]
