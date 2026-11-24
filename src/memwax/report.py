"""Render a ScanReport as terminal text, JSON, or a self-contained HTML page."""

from __future__ import annotations

import html
import json
import os
import sys

from memwax.detectors.base import Severity
from memwax.scanner import ScanReport

_ANSI = {
    Severity.CRITICAL: "\033[1;37;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[2m",
}
_RESET = "\033[0m"


def use_color(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def render_text(
    report: ScanReport, *, min_severity: Severity = Severity.LOW, color: bool = False
) -> str:
    def tag(sev: Severity) -> str:
        label = f"{sev.name:<8}"
        return f"{_ANSI[sev]}{label}{_RESET}" if color else label

    lines = [f"memwax {report.version} scan of {report.root} ({report.adapter} adapter)"]
    integrity = report.integrity
    if integrity.get("baseline_digest"):
        state = "OK" if integrity.get("integrity_ok") else "FAILED"
        lines.append(
            f"Amber baseline: {state} (from {integrity.get('baseline_created_at')}, "
            f"signer {integrity.get('signer') or '?'})"
        )
    elif report.integrity:
        lines.append(f"Change log: {'OK' if integrity.get('log_ok') else 'BROKEN'}")
    else:
        lines.append("Amber baseline: none (run `memwax amber create` to enable drift checks)")
    lines.append("")

    shown = [f for f in report.findings if f.severity >= min_severity]
    current_file = None
    for finding in shown:
        file_name = finding.path.split("#", 1)[0]
        if file_name != current_file:
            current_file = file_name
            lines.append(file_name)
        where = f"{finding.line}:{finding.column or 1}" if finding.line else "-"
        lines.append(f"  {tag(finding.severity)} {where:<8} {finding.rule:<28} {finding.message}")
        if finding.excerpt:
            lines.append(f"  {'':8} {'':8} {finding.excerpt}")
    if not shown:
        lines.append("No findings at or above " + min_severity.label + ".")
    hidden = len(report.findings) - len(shown)
    lines.append("")
    counts = report.counts()
    summary = ", ".join(f"{n} {name}" for name, n in counts.items() if n)
    lines.append(
        f"{len(report.files)} file(s) scanned, {len(report.findings)} finding(s)"
        + (f": {summary}" if summary else "")
        + (f" ({hidden} below {min_severity.label} not shown)" if hidden else "")
    )
    return "\n".join(lines) + "\n"


def render_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=True) + "\n"


_CSS = """
:root{--bg:#fbfaf7;--fg:#1d1d1b;--muted:#6b6a65;--line:#e4e1d9;--card:#fff;
--crit:#9b1c1c;--high:#c2410c;--med:#a16207;--low:#0e7490;--info:#6b7280}
@media (prefers-color-scheme:dark){:root{--bg:#16150f;--fg:#ece9e1;--muted:#a19e94;
--line:#33312a;--card:#1f1e18;--crit:#f87171;--high:#fb923c;--med:#facc15;--low:#22d3ee;
--info:#9ca3af}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1000px;margin:0 auto;padding:32px 16px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 8px}
.muted{color:var(--muted)}.tiles{display:flex;flex-wrap:wrap;gap:10px;margin:18px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 14px;
min-width:110px}.tile b{display:block;font-size:22px}
.wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;background:var(--card);
border:1px solid var(--line);border-radius:8px}th,td{text-align:left;padding:8px 10px;
border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;
text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
code{font:13px/1.4 ui-monospace,Consolas,monospace;word-break:break-word}
.sev{font-weight:700;font-size:12px;text-transform:uppercase}
.critical{color:var(--crit)}.high{color:var(--high)}.medium{color:var(--med)}
.low{color:var(--low)}.info{color:var(--info)}
.ok{color:#15803d}.bad{color:var(--crit)}
"""


def render_html(report: ScanReport, *, min_severity: Severity = Severity.INFO) -> str:
    e = html.escape
    counts = report.counts()
    tiles = "".join(
        f'<div class="tile"><b class="{name}">{n}</b>{name}</div>' for name, n in counts.items()
    )
    integrity = report.integrity
    if integrity.get("baseline_digest"):
        ok = integrity.get("integrity_ok")
        drift = integrity.get("drift", {})
        status = (
            f'<p>Amber baseline: <b class="{"ok" if ok else "bad"}">'
            f"{'signature OK' if ok else 'INTEGRITY FAILED'}</b> &middot; created "
            f"{e(str(integrity.get('baseline_created_at')))} &middot; drift: "
            f"{len(drift.get('added', []))} added, {len(drift.get('changed', []))} changed, "
            f"{len(drift.get('removed', []))} removed</p>"
        )
    else:
        status = '<p class="muted">No amber baseline; drift checks were skipped.</p>'
    rows = []
    for f in report.findings:
        if f.severity < min_severity:
            continue
        where = f"{f.line}:{f.column or 1}" if f.line else ""
        rows.append(
            f'<tr><td class="sev {f.severity.label}">{f.severity.label}</td>'
            f"<td><code>{e(f.path)}</code><br><span class='muted'>{e(where)}</span></td>"
            f"<td><code>{e(f.rule)}</code></td><td>{e(f.message)}"
            + (f"<br><code class='muted'>{e(f.excerpt)}</code>" if f.excerpt else "")
            + "</td></tr>"
        )
    table = (
        '<div class="wrap"><table><thead><tr><th>Severity</th><th>Location</th><th>Rule</th>'
        "<th>Finding</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>"
        if rows
        else "<p>No findings.</p>"
    )
    files = "".join(f"<li><code>{e(name)}</code></li>" for name in report.files)
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>memwax report</title><style>{_CSS}</style></head><body><main>"
        f"<h1>memwax scan report</h1><p class='muted'>{e(report.root)} &middot; "
        f"{e(report.adapter)} adapter &middot; {e(report.generated_at)} &middot; "
        f"memwax {e(report.version)}</p>{status}<div class='tiles'>{tiles}</div>"
        f"<h2>Findings</h2>{table}<h2>Files scanned ({len(report.files)})</h2>"
        f"<ul>{files}</ul></main></body></html>\n"
    )
