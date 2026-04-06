from datetime import datetime, timezone
from jinja2 import Template
from evadex.reporters.base import BaseReporter
from evadex.core.result import ScanResult, SeverityLevel

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>evadex DLP Evasion Report</title>
<style>
  :root { --bg: #0f1117; --surface: #1a1d27; --border: #2a2d3a; --text: #e2e8f0; --muted: #8892a4; --green: #22c55e; --red: #ef4444; --orange: #f97316; --blue: #3b82f6; --accent: #6366f1; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; line-height: 1.5; padding: 24px; }
  h1 { font-size: 24px; font-weight: 700; color: var(--accent); margin-bottom: 4px; }
  .meta { color: var(--muted); font-size: 12px; margin-bottom: 24px; }
  .cards { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px 24px; min-width: 120px; }
  .card-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); margin-bottom: 4px; }
  .card-value { font-size: 28px; font-weight: 700; }
  .card.pass .card-value { color: var(--green); }
  .card.fail .card-value { color: var(--red); }
  .card.error .card-value { color: var(--orange); }
  .card.total .card-value { color: var(--text); }
  .card.rate .card-value { color: var(--blue); }
  .chart-wrap { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 24px; }
  .chart-label { font-size: 12px; color: var(--muted); margin-bottom: 8px; }
  .bar-track { height: 20px; background: var(--border); border-radius: 4px; overflow: hidden; display: flex; }
  .bar-pass { background: var(--green); height: 100%; }
  .bar-fail { background: var(--red); height: 100%; }
  .bar-error { background: var(--orange); height: 100%; }
  .bar-legend { display: flex; gap: 16px; margin-top: 8px; font-size: 12px; color: var(--muted); }
  .dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; margin-right: 4px; vertical-align: middle; }
  table { width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 8px; overflow: hidden; border: 1px solid var(--border); }
  th { background: #12151f; text-align: left; padding: 10px 12px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); border-bottom: 1px solid var(--border); font-weight: 600; }
  td { padding: 9px 12px; border-bottom: 1px solid var(--border); font-size: 13px; vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: rgba(255,255,255,0.03); }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .badge-pass { background: rgba(34,197,94,0.15); color: var(--green); }
  .badge-fail { background: rgba(239,68,68,0.15); color: var(--red); }
  .badge-error { background: rgba(249,115,22,0.15); color: var(--orange); }
  .variant-cell { font-family: monospace; font-size: 12px; max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .strategy-badge { display: inline-block; padding: 1px 6px; border-radius: 4px; font-size: 10px; background: var(--border); color: var(--muted); }
  .cat { color: var(--blue); font-size: 12px; }
  .gen { color: var(--accent); font-size: 12px; }
</style>
</head>
<body>
<h1>evadex DLP Evasion Report</h1>
<div class="meta">Generated {{ timestamp }} &bull; {{ total }} tests run</div>

<div class="cards">
  <div class="card total"><div class="card-label">Total</div><div class="card-value">{{ total }}</div></div>
  <div class="card pass"><div class="card-label">Detected</div><div class="card-value">{{ passes }}</div></div>
  <div class="card fail"><div class="card-label">Evaded</div><div class="card-value">{{ fails }}</div></div>
  <div class="card error"><div class="card-label">Errors</div><div class="card-value">{{ errors }}</div></div>
  <div class="card rate"><div class="card-label">Detection Rate</div><div class="card-value">{{ pass_rate }}%</div></div>
</div>

<div class="chart-wrap">
  <div class="chart-label">Detection breakdown</div>
  <div class="bar-track">
    <div class="bar-pass" style="width: {{ pass_pct }}%"></div>
    <div class="bar-fail" style="width: {{ fail_pct }}%"></div>
    <div class="bar-error" style="width: {{ error_pct }}%"></div>
  </div>
  <div class="bar-legend">
    <span><span class="dot" style="background:var(--green)"></span>Detected ({{ passes }})</span>
    <span><span class="dot" style="background:var(--red)"></span>Evaded ({{ fails }})</span>
    <span><span class="dot" style="background:var(--orange)"></span>Error ({{ errors }})</span>
  </div>
</div>

<table>
<thead>
  <tr>
    <th>Payload</th>
    <th>Category</th>
    <th>Generator</th>
    <th>Technique</th>
    <th>Strategy</th>
    <th>Variant</th>
    <th>Result</th>
    <th>ms</th>
  </tr>
</thead>
<tbody>
{% for r in results %}
<tr>
  <td>{{ r.payload.label }}</td>
  <td><span class="cat">{{ r.payload.category.value }}</span></td>
  <td><span class="gen">{{ r.variant.generator }}</span></td>
  <td>{{ r.variant.transform_name }}</td>
  <td><span class="strategy-badge">{{ r.variant.strategy }}</span></td>
  <td class="variant-cell" title="{{ r.variant.value | e }}">{{ r.variant.value[:60] }}{% if r.variant.value | length > 60 %}&hellip;{% endif %}</td>
  <td>
    {% if r.error %}<span class="badge badge-error">error</span>
    {% elif r.detected %}<span class="badge badge-pass">detected</span>
    {% else %}<span class="badge badge-fail">evaded</span>{% endif %}
  </td>
  <td>{{ "%.1f" | format(r.duration_ms) }}</td>
</tr>
{% endfor %}
</tbody>
</table>
</body>
</html>"""


class HtmlReporter(BaseReporter):
    def render(self, results: list[ScanResult]) -> str:
        total  = len(results)
        passes = sum(1 for r in results if r.severity == SeverityLevel.PASS)
        fails  = sum(1 for r in results if r.severity == SeverityLevel.FAIL)
        errors = sum(1 for r in results if r.severity == SeverityLevel.ERROR)

        pass_pct  = round(passes / total * 100, 1) if total else 0
        fail_pct  = round(fails  / total * 100, 1) if total else 0
        error_pct = round(errors / total * 100, 1) if total else 0

        return Template(TEMPLATE).render(
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            total=total,
            passes=passes,
            fails=fails,
            errors=errors,
            pass_rate=round(passes / total * 100, 1) if total else 0,
            pass_pct=pass_pct,
            fail_pct=fail_pct,
            error_pct=error_pct,
            results=results,
        )
