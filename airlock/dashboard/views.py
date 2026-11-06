"""Server-rendered HTML for the dashboard. Every value from the audit log is escaped."""

from __future__ import annotations

import json
from datetime import datetime
from html import escape
from typing import Any
from urllib.parse import urlencode

from airlock.dashboard.data import Filters, Flow
from airlock.report import VERDICTS, Report

NAV = (("/", "Timeline"), ("/flows", "Flows"), ("/tools", "Tools"), ("/report", "Report"))


def e(value: Any) -> str:
    return escape("" if value is None else str(value), quote=True)


def when(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def page(title: str, body: str, active: str = "/", notice: str | None = None) -> str:
    links = "".join(
        f'<a href="{href}"{" class=active" if href == active else ""}>{label}</a>'
        for href, label in NAV
    )
    flash = f'<p class="notice">{e(notice)}</p>' if notice else ""
    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        '<meta name=viewport content="width=device-width, initial-scale=1">'
        f"<title>{e(title)} · Airlock</title>"
        '<link rel=stylesheet href="/static/app.css"><script src="/static/app.js" defer></script>'
        f"</head><body><header><strong>Airlock</strong><nav>{links}</nav></header>"
        f"<main><h1>{e(title)}</h1>{flash}{body}</main></body></html>"
    )


def verdict_badge(verdict: str | None, would_have: str | None = None) -> str:
    shown = verdict or "?"
    badge = f'<span class="badge {e(shown.lower())}">{e(shown)}</span>'
    if would_have and would_have != shown:
        badge += f' <span class="badge shadow" title="shadow mode">would {e(would_have)}</span>'
    return badge


def timeline_row(row: dict[str, Any]) -> str:
    reasons = "; ".join(str(r) for r in row["reasons"])
    if len(reasons) > 140:
        reasons = reasons[:137] + "..."
    return (
        f'<tr data-id="{int(row["id"])}"><td>{e(when(row["ts"]))}</td>'
        f"<td>{e(row['direction'])}</td>"
        f"<td>{e(row['server_id'])}.{e(row['tool_name'])}</td>"
        f"<td>{verdict_badge(row['verdict'], row['would_have'])}</td>"
        f"<td><code>{e(row['rule'] or '-')}</code></td>"
        f"<td>{e(reasons)}</td>"
        f'<td><a href="/decision/{int(row["id"])}">details</a></td></tr>'
    )


def timeline(rows: list[dict[str, Any]], filters: Filters) -> str:
    def select(name: str, options: tuple[str, ...], current: str | None) -> str:
        choices = "".join(
            f'<option value="{e(o)}"{" selected" if o == (current or "") else ""}>'
            f"{e(o) or 'any'}</option>"
            for o in ("", *options)
        )
        return f'<label>{name} <select name="{name}">{choices}</select></label>'

    form = (
        '<form class="filters" method=get action="/">'
        + select("verdict", VERDICTS, filters.verdict)
        + select("direction", ("call", "result"), filters.direction)
        + f'<label>server <input name=server value="{e(filters.server)}"></label>'
        + f'<label>tool <input name=tool value="{e(filters.tool)}"></label>'
        + f'<label>since <input name=since placeholder=24h value="{e(filters.since)}"></label>'
        + "<button>Filter</button></form>"
    )
    newest = max((int(row["id"]) for row in rows), default=0)
    query = urlencode({k: v for k, v in vars(filters).items() if v and k != "limit"})
    body = "".join(timeline_row(row) for row in rows) or (
        "<tr class=empty><td colspan=7>No decisions yet.</td></tr>"
    )
    return form + (
        f'<table id=timeline data-live="/events?{e(query)}" data-after="{newest}">'
        "<thead><tr><th>Time</th><th>Dir</th><th>Tool</th><th>Verdict</th><th>Rule</th>"
        f"<th>Reasons</th><th></th></tr></thead><tbody>{body}</tbody></table>"
        "<p class=hint>New decisions appear live.</p>"
    )


def detail(row: dict[str, Any], csrf: str) -> str:
    reasons = "".join(f"<li>{e(r)}</li>" for r in row["reasons"]) or "<li>none</li>"
    scores = (
        "".join(
            f"<tr><td><code>{e(k)}</code></td><td>{float(v):.3f}</td></tr>"
            for k, v in sorted(row["scores"].items())
        )
        or "<tr><td colspan=2>none</td></tr>"
    )
    preview = row["args_preview"] if row["direction"] == "call" else row["result_preview"]
    return (
        "<dl>"
        f"<dt>Time</dt><dd>{e(when(row['ts']))}</dd>"
        f"<dt>Session</dt><dd><code>{e(row['session_id'])}</code></dd>"
        f"<dt>Tool</dt><dd>{e(row['server_id'])}.{e(row['tool_name'])} ({e(row['direction'])})</dd>"
        f"<dt>Verdict</dt><dd>{verdict_badge(row['verdict'], row['would_have'])}</dd>"
        f"<dt>Rule</dt><dd><code>{e(row['rule'] or '-')}</code></dd>"
        f"<dt>Latency</dt><dd>{float(row['latency_ms']):.1f} ms</dd></dl>"
        f"<h2>Reasons</h2><ul>{reasons}</ul>"
        f"<h2>Scores</h2><table>{scores}</table>"
        f"<h2>{'Arguments' if row['direction'] == 'call' else 'Result'} (masked)</h2>"
        f"<pre>{e(preview or '(empty)')}</pre>"
        f'<form method=post action="/decision/{int(row["id"])}/false-positive">'
        f'<input type=hidden name=csrf value="{e(csrf)}">'
        "<button>Mark as false positive</button></form>"
        "<p class=hint>Stores this decision and its text in data_dir/feedback/ for the next "
        "classifier training round.</p>"
    )


def _box(x: int, y: int, label: str, kind: str) -> str:
    shown = label if len(label) <= 32 else label[:29] + "..."
    return (
        f'<g class="node {kind}"><rect x="{x}" y="{y}" width="220" height="44" rx="6"/>'
        f'<text x="{x + 110}" y="{y + 27}" text-anchor="middle">{e(shown)}</text></g>'
    )


def flow_svg(flow: Flow) -> str:
    arrow = '<line x1="{a}" y1="22" x2="{b}" y2="22" marker-end="url(#arrow)"/>'
    return (
        '<svg class=flow viewBox="0 0 760 44" role=img '
        f'aria-label="{e(flow.source)} to {e(flow.value)} to {e(flow.sink)}">'
        '<defs><marker id=arrow viewBox="0 0 10 10" refX=10 refY=5 markerWidth=8 '
        'markerHeight=8 orient=auto><path d="M0,0 L10,5 L0,10 z"/></marker></defs>'
        + _box(0, 0, flow.source, "source")
        + arrow.format(a=220, b=268)
        + _box(270, 0, flow.value, "value")
        + arrow.format(a=490, b=538)
        + _box(540, 0, f"{flow.sink} ({flow.argument})", "sink")
        + "</svg>"
    )


def flows_page(items: list[Flow]) -> str:
    if not items:
        return "<p>No tainted values were stopped in this period.</p>"
    return "".join(
        f"<section class=flowrow><p>{verdict_badge(f.verdict)} <code>{e(f.rule)}</code> · "
        f'<a href="/decision/{f.decision_id}">decision {f.decision_id}</a></p>'
        f"{flow_svg(f)}</section>"
        for f in items
    )


def tools_page(rows: list[dict[str, Any]], csrf: str) -> str:
    out = []
    for row in rows:
        labels = ", ".join(json.loads(row.get("labels") or "[]")) or "-"
        action = ""
        if row["status"] in {"pending", "quarantined"}:
            action = (
                '<form method=post action="/tools/approve">'
                f'<input type=hidden name=csrf value="{e(csrf)}">'
                f'<input type=hidden name=server value="{e(row["server_id"])}">'
                f'<input type=hidden name=tool value="{e(row["tool_name"])}">'
                "<button>Approve</button></form>"
            )
        out.append(
            f"<tr><td>{e(row['server_id'])}</td><td>{e(row['tool_name'])}</td>"
            f'<td><span class="badge {e(row["status"])}">{e(row["status"])}</span></td>'
            f"<td>{e(labels)}</td><td>{e(row.get('label_origin'))}</td>"
            f"<td><code>{e(str(row['hash'])[:12])}</code></td>"
            f"<td>{e(row.get('status_reason') or '-')}</td><td>{action}</td></tr>"
        )
    body = "".join(out) or "<tr class=empty><td colspan=8>No tools registered yet.</td></tr>"
    return (
        "<table><thead><tr><th>Server</th><th>Tool</th><th>Status</th><th>Labels</th>"
        "<th>Label origin</th><th>Hash</th><th>Reason</th><th></th></tr></thead>"
        f"<tbody>{body}</tbody></table>"
    )


def report_page(report: Report, since: str) -> str:
    verdicts = "".join(
        f"<tr><td>{verdict_badge(v)}</td><td>{report.by_verdict.get(v, 0)}</td></tr>"
        for v in VERDICTS
    )
    rules = (
        "".join(
            f"<tr><td><code>{e(rule)}</code></td><td>{count}</td></tr>"
            for rule, count in report.top_rules
        )
        or "<tr><td colspan=2>none</td></tr>"
    )
    shadow = (
        "".join(
            f"<tr><td>{e(tool)}</td><td>{e(verdict)}</td><td>{count}</td></tr>"
            for tool, verdict, count in report.shadow_tools
        )
        or "<tr><td colspan=3>nothing</td></tr>"
    )
    quarantined = (
        "".join(
            f"<li>{e(server)}.{e(tool)}: {e(reason)}</li>"
            for server, tool, reason in report.quarantined
        )
        or "<li>none</li>"
    )
    trifectas = "".join(f"<li>{e(t.message(limit=10))}</li>" for t in report.trifectas) or (
        "<li>none</li>"
    )
    alerts = (
        "".join(
            f"<li>{e(when(a['ts']))} {e(a['server_id'])}.{e(a['tool_name'])}: "
            f"{e(a['message'])}</li>"
            for a in report.honeytoken_alerts
        )
        or "<li>none</li>"
    )
    return (
        f'<form class=filters method=get action="/report"><label>since '
        f'<input name=since value="{e(since)}"></label><button>Show</button></form>'
        f"<p>{e(when(report.since))} to {e(when(report.until))}: {report.total} decisions "
        f"(calls {report.by_direction.get('call', 0)}, "
        f"results {report.by_direction.get('result', 0)}).</p>"
        f"<div class=grid><section><h2>Decisions</h2><table>{verdicts}</table></section>"
        f"<section><h2>Top rules</h2><table>{rules}</table></section></div>"
        f"<h2>Shadow mode: would have been stopped</h2><table>{shadow}</table>"
        f"<h2>Quarantined tools</h2><ul>{quarantined}</ul>"
        f"<h2>Lethal-trifecta warnings</h2><ul>{trifectas}</ul>"
        f"<h2>Honeytoken alerts</h2><ul>{alerts}</ul>"
    )


__all__ = [
    "detail",
    "flow_svg",
    "flows_page",
    "page",
    "report_page",
    "timeline",
    "timeline_row",
    "tools_page",
]
