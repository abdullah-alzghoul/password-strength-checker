"""Export StrengthReport results to JSON and HTML formats."""

import html
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from src.core.scorer import StrengthReport

STRENGTH_HTML_COLORS = {
    "Compromised": "#c026d3",
    "Very Weak": "#dc2626",
    "Weak": "#ef4444",
    "Fair": "#eab308",
    "Strong": "#22c55e",
    "Very Strong": "#16a34a",
}


def report_to_dict(report: StrengthReport) -> dict:
    """Convert a StrengthReport into a plain, JSON-safe dict."""
    data = asdict(report)
    data["strength"] = report.strength.value
    data["entropy_detail"]["strength"] = report.entropy_detail.strength.value
    data["generated_at"] = datetime.now(timezone.utc).isoformat()
    return data


def export_json(report: StrengthReport, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report_to_dict(report), indent=2, default=str),
        encoding="utf-8",
    )
    return path


def _warnings_html(warnings: list[str]) -> str:
    if not warnings:
        return '<p class="clean">No weak patterns detected.</p>'
    items = "".join(f"<li>{html.escape(w)}</li>" for w in warnings)
    return f'<ul class="warnings">{items}</ul>'


def export_html(report: StrengthReport, path: str | Path) -> Path:
    color = STRENGTH_HTML_COLORS.get(report.strength.value, "#6b7280")
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    breach = report.breach_detail
    breach_status = "Found in breach" if breach.is_breached else ("Not found" if breach.checked else "Not checked")

    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Password Strength Report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, sans-serif; background: #0f172a; color: #e2e8f0;
         max-width: 640px; margin: 40px auto; padding: 0 20px; }}
  h1 {{ font-size: 1.4rem; }}
  .badge {{ display: inline-block; padding: 4px 14px; border-radius: 999px;
            background: {color}; color: #fff; font-weight: 600; }}
  table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
  td {{ padding: 8px 0; border-bottom: 1px solid #1e293b; }}
  td:first-child {{ color: #94a3b8; width: 45%; }}
  ul.warnings {{ background: #1e293b; border-left: 3px solid {color}; padding: 12px 24px; }}
  .clean {{ color: #22c55e; }}
  .footer {{ margin-top: 30px; font-size: 0.8rem; color: #64748b; }}
</style>
</head>
<body>
  <h1>Password Strength Report</h1>
  <p><span class="badge">{html.escape(report.strength.value)}</span></p>
  <table>
    <tr><td>Length</td><td>{report.password_length}</td></tr>
    <tr><td>Raw entropy</td><td>{report.raw_entropy_bits} bits</td></tr>
    <tr><td>Effective entropy</td><td>{report.effective_entropy_bits} bits</td></tr>
    <tr><td>Common password match</td><td>{"Yes" if report.pattern_detail.is_common_password else "No"}</td></tr>
    <tr><td>Breach check</td><td>{breach_status}</td></tr>
  </table>
  <h2>Warnings</h2>
  {_warnings_html(report.warnings)}
  <p class="footer">Generated {generated_at} &middot; Password Strength Checker + Analyzer</p>
</body>
</html>"""

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(document, encoding="utf-8")
    return path


def export_report(report: StrengthReport, base_path: str | Path) -> tuple[Path, Path]:
    """Export both JSON and HTML using the same base filename (without extension)."""
    base = Path(base_path)
    json_path = export_json(report, base.with_suffix(".json"))
    html_path = export_html(report, base.with_suffix(".html"))
    return json_path, html_path