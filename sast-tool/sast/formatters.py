"""
Output formatters: terminal (rich), JSON, and HTML report.
"""

import json
from pathlib import Path
from datetime import datetime
from .scanner import ScanResult, Finding

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


SEVERITY_COLORS = {
    "CRITICAL": "#ff2d55",
    "HIGH":     "#ff6b35",
    "MEDIUM":   "#ffd60a",
    "LOW":      "#30d158",
    "INFO":     "#64d2ff",
}

SEVERITY_ICONS = {
    "CRITICAL": "💀",
    "HIGH":     "🔴",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "🔵",
}


# ─── Terminal Output ──────────────────────────────────────────────────────────

def print_terminal(result: ScanResult, verbose: bool = False) -> None:
    if RICH_AVAILABLE:
        _print_rich(result, verbose)
    else:
        _print_plain(result, verbose)


def _print_rich(result: ScanResult, verbose: bool):
    console = Console()
    summary = result.summary
    total = len(result.findings)

    console.print()
    console.print(Panel.fit(
        f"[bold]🔍 SAST Scan Complete[/bold]\n"
        f"Target: [cyan]{result.target_path}[/cyan]\n"
        f"Files scanned: [white]{result.files_scanned}[/white]  |  "
        f"Skipped: [dim]{result.files_skipped}[/dim]  |  "
        f"Duration: [white]{result.scan_duration_seconds:.2f}s[/white]",
        border_style="bright_blue"
    ))

    # Summary table
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold white")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")

    for sev, color in SEVERITY_COLORS.items():
        count = summary.get(sev, 0)
        style = f"bold {color}" if count > 0 else "dim"
        table.add_row(f"{SEVERITY_ICONS[sev]} {sev}", str(count), style=style)

    table.add_row("─" * 12, "─" * 6, style="dim")
    table.add_row("[bold]TOTAL[/bold]", f"[bold]{total}[/bold]")
    console.print(table)

    if total == 0:
        console.print("\n[bold green]✅ No findings. Clean scan![/bold green]\n")
        return

    console.print()

    for finding in result.findings:
        color = SEVERITY_COLORS.get(finding.severity, "white")
        icon = SEVERITY_ICONS.get(finding.severity, "•")

        header = (
            f"{icon} [{color}]{finding.severity}[/{color}]  "
            f"[bold]{finding.title}[/bold]  "
            f"[dim]{finding.rule_id}[/dim]"
        )
        body = (
            f"[cyan]{finding.file_path}[/cyan]:[yellow]{finding.line_number}[/yellow]\n"
            f"[dim]{finding.line_content}[/dim]\n\n"
            f"[white]{finding.description}[/white]\n"
        )
        if verbose:
            body += f"\n[bold]Remediation:[/bold] {finding.remediation}\n"
            if finding.cwe:
                body += f"[bold]CWE:[/bold] {finding.cwe}  "
            if finding.owasp:
                body += f"[bold]OWASP:[/bold] {finding.owasp}"

        console.print(Panel(body, title=header, border_style=color, title_align="left"))

    console.print()


def _print_plain(result: ScanResult, verbose: bool):
    print(f"\n=== SAST Scan Results ===")
    print(f"Target: {result.target_path}")
    print(f"Files scanned: {result.files_scanned}, Skipped: {result.files_skipped}")
    print(f"Duration: {result.scan_duration_seconds:.2f}s")
    print(f"Total findings: {len(result.findings)}\n")

    for f in result.findings:
        print(f"[{f.severity}] {f.title} ({f.rule_id})")
        print(f"  {f.file_path}:{f.line_number}")
        print(f"  {f.line_content}")
        if verbose:
            print(f"  Fix: {f.remediation}")
        print()


# ─── JSON Output ──────────────────────────────────────────────────────────────

def write_json(result: ScanResult, output_path: str) -> str:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(result.to_dict(), f, indent=2, default=str)
    return str(path)


# ─── HTML Report ─────────────────────────────────────────────────────────────

def write_html(result: ScanResult, output_path: str) -> str:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    html = _build_html(result)
    path.write_text(html, encoding="utf-8")
    return str(path)


def _build_html(result: ScanResult) -> str:
    summary = result.summary
    total = len(result.findings)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    findings_html = ""
    for f in result.findings:
        cwe_badge = f'<span class="badge badge-cwe">{f.cwe}</span>' if f.cwe else ""
        owasp_badge = f'<span class="badge badge-owasp">{f.owasp}</span>' if f.owasp else ""
        findings_html += f"""
        <div class="finding severity-{f.severity.lower()}">
            <div class="finding-header">
                <span class="severity-badge {f.severity.lower()}">{f.severity}</span>
                <span class="finding-title">{_esc(f.title)}</span>
                <span class="rule-id">{_esc(f.rule_id)}</span>
                <span class="confidence">confidence: {f.confidence}</span>
            </div>
            <div class="finding-location">
                <span class="file-path">📄 {_esc(f.file_path)}</span>
                <span class="line-number">line {f.line_number}</span>
                {cwe_badge}{owasp_badge}
            </div>
            <pre class="code-snippet"><code>{_esc(f.line_content)}</code></pre>
            <p class="description">{_esc(f.description)}</p>
            <div class="remediation">
                <span class="remediation-label">🔧 Remediation</span>
                <p>{_esc(f.remediation)}</p>
            </div>
        </div>"""

    severity_bars = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = summary.get(sev, 0)
        severity_bars += f"""
            <div class="stat-card {sev.lower()}">
                <div class="stat-count">{count}</div>
                <div class="stat-label">{sev}</div>
            </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SAST Report — {_esc(result.target_path)}</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@400;600;700;800&display=swap');

        *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

        :root {{
            --bg: #0a0a0f;
            --surface: #111118;
            --surface2: #1a1a24;
            --border: #2a2a3a;
            --text: #e8e8f0;
            --text-dim: #6b6b80;
            --critical: #ff2d55;
            --high: #ff6b35;
            --medium: #ffd60a;
            --low: #30d158;
            --info: #64d2ff;
            --accent: #7b61ff;
        }}

        body {{
            font-family: 'Syne', sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            padding: 0;
        }}

        .header {{
            background: linear-gradient(135deg, #0d0d1a 0%, #1a0d2e 50%, #0d1a1a 100%);
            border-bottom: 1px solid var(--border);
            padding: 48px;
            position: relative;
            overflow: hidden;
        }}

        .header::before {{
            content: '';
            position: absolute;
            top: -50%;
            left: -10%;
            width: 500px;
            height: 500px;
            background: radial-gradient(circle, rgba(123,97,255,0.08) 0%, transparent 70%);
            pointer-events: none;
        }}

        .header-title {{
            font-size: 2.4rem;
            font-weight: 800;
            letter-spacing: -0.03em;
            background: linear-gradient(135deg, #fff 30%, var(--accent));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}

        .header-meta {{
            color: var(--text-dim);
            font-size: 0.85rem;
            margin-top: 10px;
            font-family: 'JetBrains Mono', monospace;
        }}

        .header-meta span {{ color: var(--text); }}

        .container {{ max-width: 1100px; margin: 0 auto; padding: 40px 48px; }}

        .stats-grid {{
            display: flex;
            gap: 12px;
            margin-bottom: 40px;
            flex-wrap: wrap;
        }}

        .stat-card {{
            flex: 1;
            min-width: 100px;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }}

        .stat-card::before {{
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 3px;
        }}

        .stat-card.critical::before {{ background: var(--critical); }}
        .stat-card.high::before {{ background: var(--high); }}
        .stat-card.medium::before {{ background: var(--medium); }}
        .stat-card.low::before {{ background: var(--low); }}
        .stat-card.info::before {{ background: var(--info); }}

        .stat-count {{ font-size: 2.2rem; font-weight: 800; }}
        .stat-card.critical .stat-count {{ color: var(--critical); }}
        .stat-card.high .stat-count {{ color: var(--high); }}
        .stat-card.medium .stat-count {{ color: var(--medium); }}
        .stat-card.low .stat-count {{ color: var(--low); }}
        .stat-card.info .stat-count {{ color: var(--info); }}

        .stat-label {{ font-size: 0.7rem; letter-spacing: 0.1em; color: var(--text-dim); margin-top: 4px; font-weight: 600; }}

        .section-title {{
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 0.12em;
            color: var(--text-dim);
            text-transform: uppercase;
            margin-bottom: 16px;
        }}

        .filters {{
            display: flex;
            gap: 8px;
            margin-bottom: 24px;
            flex-wrap: wrap;
        }}

        .filter-btn {{
            padding: 6px 16px;
            border-radius: 20px;
            border: 1px solid var(--border);
            background: var(--surface);
            color: var(--text-dim);
            font-family: 'Syne', sans-serif;
            font-size: 0.8rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.15s;
        }}

        .filter-btn:hover, .filter-btn.active {{
            border-color: var(--accent);
            color: var(--text);
            background: rgba(123,97,255,0.1);
        }}

        .finding {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 16px;
            transition: border-color 0.15s;
        }}

        .finding:hover {{ border-color: #3a3a50; }}

        .finding.severity-critical {{ border-left: 3px solid var(--critical); }}
        .finding.severity-high {{ border-left: 3px solid var(--high); }}
        .finding.severity-medium {{ border-left: 3px solid var(--medium); }}
        .finding.severity-low {{ border-left: 3px solid var(--low); }}
        .finding.severity-info {{ border-left: 3px solid var(--info); }}

        .finding-header {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 10px;
            flex-wrap: wrap;
        }}

        .severity-badge {{
            font-size: 0.65rem;
            font-weight: 700;
            letter-spacing: 0.1em;
            padding: 3px 10px;
            border-radius: 4px;
        }}

        .severity-badge.critical {{ background: rgba(255,45,85,0.15); color: var(--critical); }}
        .severity-badge.high {{ background: rgba(255,107,53,0.15); color: var(--high); }}
        .severity-badge.medium {{ background: rgba(255,214,10,0.15); color: var(--medium); }}
        .severity-badge.low {{ background: rgba(48,209,88,0.15); color: var(--low); }}
        .severity-badge.info {{ background: rgba(100,210,255,0.15); color: var(--info); }}

        .finding-title {{ font-weight: 700; font-size: 0.95rem; }}
        .rule-id {{ font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: var(--text-dim); }}
        .confidence {{ font-size: 0.72rem; color: var(--text-dim); margin-left: auto; }}

        .finding-location {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 12px;
            flex-wrap: wrap;
        }}

        .file-path {{ font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: #64d2ff; }}
        .line-number {{ font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: var(--text-dim); }}

        .badge {{
            font-size: 0.68rem;
            padding: 2px 8px;
            border-radius: 3px;
            font-weight: 600;
        }}

        .badge-cwe {{ background: rgba(123,97,255,0.15); color: #a78bfa; }}
        .badge-owasp {{ background: rgba(255,107,53,0.12); color: var(--high); }}

        .code-snippet {{
            background: #0d0d15;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px 16px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            overflow-x: auto;
            margin-bottom: 12px;
            color: #a8b4d0;
        }}

        .description {{ font-size: 0.88rem; color: var(--text-dim); margin-bottom: 14px; line-height: 1.6; }}

        .remediation {{
            background: rgba(48,209,88,0.05);
            border: 1px solid rgba(48,209,88,0.15);
            border-radius: 8px;
            padding: 14px 16px;
        }}

        .remediation-label {{ font-size: 0.75rem; font-weight: 700; color: var(--low); letter-spacing: 0.05em; }}
        .remediation p {{ font-size: 0.85rem; color: var(--text-dim); margin-top: 6px; line-height: 1.6; }}

        .empty-state {{
            text-align: center;
            padding: 80px 20px;
            color: var(--text-dim);
        }}

        .empty-state .icon {{ font-size: 3rem; margin-bottom: 16px; }}
        .empty-state h3 {{ font-size: 1.2rem; color: var(--low); margin-bottom: 8px; }}

        footer {{
            text-align: center;
            padding: 40px;
            color: var(--text-dim);
            font-size: 0.78rem;
            border-top: 1px solid var(--border);
            margin-top: 60px;
        }}

        .hidden {{ display: none !important; }}
    </style>
</head>
<body>
    <div class="header">
        <div class="header-title">SAST Security Report</div>
        <div class="header-meta">
            Target: <span>{_esc(result.target_path)}</span> &nbsp;·&nbsp;
            Scan ID: <span>{result.scan_id}</span> &nbsp;·&nbsp;
            Generated: <span>{generated_at}</span> &nbsp;·&nbsp;
            Files: <span>{result.files_scanned} scanned, {result.files_skipped} skipped</span> &nbsp;·&nbsp;
            Duration: <span>{result.scan_duration_seconds:.2f}s</span>
        </div>
    </div>

    <div class="container">
        <div class="stats-grid">
            {severity_bars}
        </div>

        <div class="section-title">Findings ({total})</div>

        <div class="filters">
            <button class="filter-btn active" onclick="filterFindings('ALL')">All ({total})</button>
            <button class="filter-btn" onclick="filterFindings('CRITICAL')">Critical ({summary.get('CRITICAL', 0)})</button>
            <button class="filter-btn" onclick="filterFindings('HIGH')">High ({summary.get('HIGH', 0)})</button>
            <button class="filter-btn" onclick="filterFindings('MEDIUM')">Medium ({summary.get('MEDIUM', 0)})</button>
            <button class="filter-btn" onclick="filterFindings('LOW')">Low ({summary.get('LOW', 0)})</button>
            <button class="filter-btn" onclick="filterFindings('INFO')">Info ({summary.get('INFO', 0)})</button>
        </div>

        <div id="findings-container">
            {'<div class="empty-state"><div class="icon">✅</div><h3>No findings detected</h3><p>Clean scan — no security issues found.</p></div>' if total == 0 else findings_html}
        </div>
    </div>

    <footer>
        Generated by <strong>SAST Tool</strong> · {generated_at}
    </footer>

    <script>
        function filterFindings(severity) {{
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');

            document.querySelectorAll('.finding').forEach(el => {{
                if (severity === 'ALL' || el.classList.contains('severity-' + severity.toLowerCase())) {{
                    el.classList.remove('hidden');
                }} else {{
                    el.classList.add('hidden');
                }}
            }});
        }}
    </script>
</body>
</html>"""


def _esc(text: str) -> str:
    return (str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))
