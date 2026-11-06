"""``airlock dashboard``: a local web UI over the audit log and tool registry.

Starlette (the framework FastAPI is built on, already installed with the MCP
SDK) and a few lines of plain JavaScript instead of FastAPI and HTMX: nothing
extra to install, and every asset ships in the package, so it works offline.

Access control:

- binds to 127.0.0.1 only (there is no option to change that);
- the printed URL carries a one-time token; using it sets an HttpOnly,
  SameSite=Strict session cookie and redirects to a URL without the token,
  after which the token no longer works;
- every request needs that cookie, a ``Host`` of ``127.0.0.1:<port>`` or
  ``localhost:<port>`` (DNS-rebinding defence), and form posts must also carry
  the page's CSRF value and come from the dashboard's own origin;
- strict Content-Security-Policy, no framing, no referrer (the token never
  leaks through a link).
"""

from __future__ import annotations

import asyncio
import hmac
import secrets
import socket
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import (
    HTMLResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from starlette.routing import Route
from starlette.staticfiles import StaticFiles

from airlock.config import AirlockConfig
from airlock.dashboard import data, views
from airlock.registry.store import ToolRegistry
from airlock.report import build_report

STATIC_DIR = Path(__file__).parent / "static"
COOKIE = "airlock_dashboard"
HOST = "127.0.0.1"
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind((HOST, 0))
        return int(sock.getsockname()[1])


class Dashboard:
    """The app plus its secrets. ``token`` is single use; ``session`` is the cookie value."""

    def __init__(self, config: AirlockConfig, port: int, poll_interval: float = 1.0) -> None:
        self.config = config
        self.port = port
        self.poll_interval = poll_interval
        self.token: str | None = secrets.token_urlsafe(24)
        self.session = secrets.token_urlsafe(32)
        self.csrf = secrets.token_urlsafe(24)
        self.audit_db = config.data_dir / "audit.db"
        self.registry_db = config.data_dir / "registry.db"

    @property
    def url(self) -> str:
        return f"http://{HOST}:{self.port}/?token={self.token}"

    # -- access control --

    def _host_ok(self, request: Request) -> bool:
        host = request.headers.get("host", "")
        return host in {f"{HOST}:{self.port}", f"localhost:{self.port}"}

    def _signed_in(self, request: Request) -> bool:
        cookie = request.cookies.get(COOKIE, "")
        return bool(cookie) and hmac.compare_digest(cookie, self.session)

    def _same_origin(self, request: Request) -> bool:
        origin = request.headers.get("origin")
        if origin is None:
            return True  # browsers send Origin on POST; SameSite=Strict covers the rest
        return origin in {f"http://{HOST}:{self.port}", f"http://localhost:{self.port}"}

    def guard(
        self, handler: Callable[[Request], Awaitable[Response]]
    ) -> Callable[[Request], Awaitable[Response]]:
        async def guarded(request: Request) -> Response:
            if not self._host_ok(request):
                return self._secure(PlainTextResponse("Bad host", status_code=400))
            token = request.query_params.get("token")
            if (
                token is not None
                and self.token is not None
                and hmac.compare_digest(token, self.token)
            ):
                self.token = None  # one-time
                response = RedirectResponse(request.url.path, status_code=303)
                response.set_cookie(
                    COOKIE, self.session, httponly=True, samesite="strict", path="/"
                )
                return self._secure(response)
            if not self._signed_in(request):
                return self._secure(
                    PlainTextResponse(
                        "Open the URL printed by `airlock dashboard`.", status_code=401
                    )
                )
            if request.method == "POST":
                form = parse_qs((await request.body()).decode("utf-8", errors="replace"))
                supplied = (form.get("csrf") or [""])[0]
                if not self._same_origin(request) or not hmac.compare_digest(supplied, self.csrf):
                    return self._secure(PlainTextResponse("Forbidden", status_code=403))
                request.state.form = {key: values[0] for key, values in form.items()}
            return self._secure(await handler(request))

        return guarded

    @staticmethod
    def _secure(response: Response) -> Response:
        for key, value in SECURITY_HEADERS.items():
            response.headers.setdefault(key, value)
        return response

    # -- pages --

    def _filters(self, request: Request) -> data.Filters:
        query = request.query_params
        return data.Filters(
            verdict=query.get("verdict") or None,
            tool=query.get("tool") or None,
            server=query.get("server") or None,
            direction=query.get("direction") or None,
            since=query.get("since") or None,
        )

    async def timeline(self, request: Request) -> Response:
        filters = self._filters(request)
        try:
            rows = data.decisions(self.audit_db, filters)
        except ValueError as exc:
            return HTMLResponse(views.page("Timeline", "", notice=str(exc)), status_code=400)
        return HTMLResponse(views.page("Timeline", views.timeline(rows, filters)))

    async def events(self, request: Request) -> Response:
        filters = self._filters(request)
        try:
            after = int(request.query_params.get("after", "0"))
        except ValueError:
            after = 0

        async def stream() -> AsyncIterator[str]:
            last = after
            yield ": connected\n\n"
            while not await request.is_disconnected():
                rows = await asyncio.to_thread(data.decisions, self.audit_db, filters, last)
                for row in reversed(rows):
                    last = max(last, int(row["id"]))
                    html = " ".join(views.timeline_row(row).splitlines())  # one SSE data line
                    yield f"event: decision\nid: {last}\ndata: {html}\n\n"
                await asyncio.sleep(self.poll_interval)
                if request.query_params.get("once"):
                    break

        return StreamingResponse(stream(), media_type="text/event-stream")

    async def detail(self, request: Request) -> Response:
        row = data.decision(self.audit_db, int(request.path_params["decision_id"]))
        if row is None:
            return HTMLResponse(
                views.page("Not found", "<p>No such decision.</p>"), status_code=404
            )
        notice = "Saved as a false positive." if request.query_params.get("saved") else None
        title = f"Decision {row['id']}"
        return HTMLResponse(views.page(title, views.detail(row, self.csrf), notice=notice))

    async def false_positive(self, request: Request) -> Response:
        decision_id = int(request.path_params["decision_id"])
        row = data.decision(self.audit_db, decision_id)
        if row is None:
            return PlainTextResponse("No such decision", status_code=404)
        data.save_feedback(self.config.data_dir, row)
        return RedirectResponse(f"/decision/{decision_id}?saved=1", status_code=303)

    async def flows(self, request: Request) -> Response:
        since = request.query_params.get("since", "7d")
        try:
            items = data.flows(self.audit_db, since=since)
        except ValueError as exc:
            return HTMLResponse(views.page("Flows", "", "/flows", str(exc)), status_code=400)
        return HTMLResponse(views.page("Flows", views.flows_page(items), "/flows"))

    async def tools(self, request: Request) -> Response:
        rows = ToolRegistry(self.registry_db).list_tools() if self.registry_db.is_file() else []
        notice = "Tool approved." if request.query_params.get("approved") else None
        return HTMLResponse(
            views.page("Tools", views.tools_page(rows, self.csrf), "/tools", notice)
        )

    async def approve(self, request: Request) -> Response:
        form: dict[str, str] = request.state.form
        server, tool = form.get("server", ""), form.get("tool", "")
        if not server or not tool:
            return PlainTextResponse("server and tool are required", status_code=400)
        ToolRegistry(self.registry_db).approve_tool(server_id=server, tool_name=tool)
        return RedirectResponse("/tools?approved=1", status_code=303)

    async def report(self, request: Request) -> Response:
        since = request.query_params.get("since", "7d")
        try:
            built = build_report(self.config, since)
        except ValueError as exc:
            return HTMLResponse(views.page("Report", "", "/report", str(exc)), status_code=400)
        return HTMLResponse(views.page("Report", views.report_page(built, since), "/report"))

    def app(self) -> Starlette:
        guard = self.guard
        static = StaticFiles(directory=STATIC_DIR)

        async def static_files(request: Request) -> Response:
            response: Any = await static.get_response(request.path_params["path"], request.scope)
            return response  # type: ignore[no-any-return]

        return Starlette(
            routes=[
                Route("/", guard(self.timeline)),
                Route("/events", guard(self.events)),
                Route("/decision/{decision_id:int}", guard(self.detail)),
                Route(
                    "/decision/{decision_id:int}/false-positive",
                    guard(self.false_positive),
                    methods=["POST"],
                ),
                Route("/flows", guard(self.flows)),
                Route("/tools", guard(self.tools)),
                Route("/tools/approve", guard(self.approve), methods=["POST"]),
                Route("/report", guard(self.report)),
                Route("/static/{path:path}", guard(static_files)),
            ]
        )


def run(config: AirlockConfig, port: int | None = None) -> None:
    """Serve on 127.0.0.1 until interrupted, printing the one-time URL."""
    import sys

    import uvicorn

    chosen = port or free_port()
    dashboard = Dashboard(config, chosen)
    sys.stdout.write(f"Airlock dashboard: {dashboard.url}\n(one-time link; Ctrl+C to stop)\n")
    sys.stdout.flush()
    uvicorn.run(dashboard.app(), host=HOST, port=chosen, log_level="warning")


__all__ = ["HOST", "Dashboard", "free_port", "run"]
