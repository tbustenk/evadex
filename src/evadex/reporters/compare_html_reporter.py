from datetime import datetime, timezone
from collections import defaultdict
from jinja2 import Template
from evadex.reporters.base import BaseReporter

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>evadex Comparison Report</title>
<style>
  :root{--bg:#0f1117;--surface:#1a1d27;--border:#2a2d3a;--text:#e2e8f0;--muted:#8892a4;--green:#22c55e;--red:#ef4444;--orange:#f97316;--blue:#3b82f6;--accent:#6366f1;--yellow:#eab308}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.5;padding:24px}
  h1{font-size:24px;font-weight:700;color:var(--accent);margin-bottom:4px}
  h2{font-size:16px;font-weight:600;color:var(--text);margin:28px 0 12px}
  .meta{color:var(--muted);font-size:12px;margin-bottom:24px}
  .cards{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:24px}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px 24px;min-width:140px}
  .card-label{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin-bottom:4px}
  .card-value{font-size:26px;font-weight:700}
  .card.pos .card-value{color:var(--green)}
  .card.neg .card-value{color:var(--red)}
  .card.neu .card-value{color:var(--text)}
  .card.rate-a .card-value{color:var(--blue)}
  .card.rate-b .card-value{color:var(--accent)}
  table{width:100%;border-collapse:collapse;background:var(--surface);border-radius:8px;overflow:hidden;border:1px solid var(--border);margin-bottom:24px}
  th{background:#12151f;text-align:left;padding:10px 12px;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);border-bottom:1px solid var(--border);font-weight:600}
  td{padding:9px 12px;border-bottom:1px solid var(--border);font-size:13px;vertical-align:middle}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:rgba(255,255,255,.03)}
  .num{text-align:right}
  .pos{color:var(--green)}
  .neg{color:var(--red)}
  .neu{color:var(--muted)}
  .badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600}
  .badge-pass{background:rgba(34,197,94,.15);color:var(--green)}
  .badge-fail{background:rgba(239,68,68,.15);color:var(--red)}
  .badge-error{background:rgba(249,115,22,.15);color:var(--orange)}
  .badge-absent{background:rgba(136,146,164,.15);color:var(--muted)}
  code{font-family:monospace;font-size:12px;background:#12151f;padding:1px 5px;border-radius:3px}
</style>
</head>
<body>
<h1>evadex Comparison Report</h1>
<div class="meta">{{ label_a }} vs {{ label_b }} &bull; Generated {{ timestamp }}</div>

<div class="cards">
  <div class="card rate-a"><div class="card-label">{{ label_a }} rate</div><div class="card-value">{{ overall.a_rate }}%</div></div>
  <div class="card rate-b"><div class="card-label">{{ label_b }} rate</div><div class="card-value">{{ overall.b_rate }}%</div></div>
  <div class="card {{ 'pos' if overall.delta >= 0 else 'neg' }}">
    <div class="card-label">Delta</div>
    <div class="card-value">{{ '+' if overall.delta >= 0 else '' }}{{ overall.delta }}pp</div>
  </div>
  <div class="card neu"><div class="card-label">Variant diffs</div><div class="card-value">{{ diffs|length }}</div></div>
</div>

<h2>Per-Category</h2>
<table>
<thead><tr>
  <th>Category</th>
  <th class="num">{{ label_a }} Pass</th><th class="num">{{ label_a }}%</th>
  <th class="num">{{ label_b }} Pass</th><th class="num">{{ label_b }}%</th>
  <th class="num">Delta</th>
</tr></thead>
<tbody>
{% for r in by_category %}
<tr>
  <td><code>{{ r.category }}</code></td>
  <td class="num">{{ r.a_pass }}</td><td class="num">{{ r.a_rate }}%</td>
  <td class="num">{{ r.b_pass }}</td><td class="num">{{ r.b_rate }}%</td>
  <td class="num {{ 'pos' if r.delta > 0 else ('neg' if r.delta < 0 else 'neu') }}">
    {{ '+' if r.delta > 0 else '' }}{{ r.delta }}pp
  </td>
</tr>
{% endfor %}
</tbody>
</table>

<h2>Per-Technique (changed only)</h2>
<table>
<thead><tr>
  <th>Generator</th><th>Technique</th>
  <th class="num">{{ label_a }}%</th>
  <th class="num">{{ label_b }}%</th>
  <th class="num">Delta</th>
</tr></thead>
<tbody>
{% for r in by_technique %}
<tr>
  <td><code>{{ r.generator }}</code></td>
  <td><code>{{ r.technique }}</code></td>
  <td class="num">{{ r.a_rate }}%</td>
  <td class="num">{{ r.b_rate }}%</td>
  <td class="num {{ 'pos' if r.delta > 0 else 'neg' }}">
    {{ '+' if r.delta > 0 else '' }}{{ r.delta }}pp
  </td>
</tr>
{% endfor %}
</tbody>
</table>

<h2>Variant Diffs ({{ diffs|length }} changed)</h2>
<table>
<thead><tr>
  <th>Payload</th><th>Category</th><th>Generator</th><th>Technique</th><th>Strategy</th>
  <th>{{ label_a }}</th><th>{{ label_b }}</th>
</tr></thead>
<tbody>
{% for d in diffs %}
<tr>
  <td>{{ d.payload_label }}</td>
  <td><code>{{ d.category }}</code></td>
  <td><code>{{ d.generator }}</code></td>
  <td><code>{{ d.technique }}</code></td>
  <td><code>{{ d.strategy }}</code></td>
  <td><span class="badge badge-{{ d.a_severity }}">{{ d.a_severity }}</span></td>
  <td><span class="badge badge-{{ d.b_severity }}">{{ d.b_severity }}</span></td>
</tr>
{% endfor %}
</tbody>
</table>
</body>
</html>"""


class CompareHtmlReporter(BaseReporter):
    def render(self, comparison: dict) -> str:  # type: ignore[override]
        total = len(comparison["diffs"])
        return Template(TEMPLATE).render(
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            label_a=comparison["label_a"],
            label_b=comparison["label_b"],
            overall=comparison["overall"],
            by_category=comparison["by_category"],
            by_technique=comparison["by_technique"],
            diffs=comparison["diffs"],
        )
