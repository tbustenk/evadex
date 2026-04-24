from datetime import datetime, timezone
from collections import defaultdict
from jinja2 import Template
from evadex.reporters.base import BaseReporter
from evadex.core.result import ScanResult, SeverityLevel
from evadex.feedback.suggestions import get_suggestions

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
  h2 { font-size: 16px; font-weight: 600; color: var(--text); margin: 24px 0 12px; }
  .meta { color: var(--muted); font-size: 12px; margin-bottom: 24px; }
  .exec-summary { background: var(--surface); border: 1px solid var(--border); border-left: 3px solid var(--accent); border-radius: 6px; padding: 16px 20px; margin-bottom: 24px; font-size: 14px; line-height: 1.6; }
  .exec-summary strong { color: var(--accent); }
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
  .conf-row { display: flex; align-items: center; gap: 12px; font-size: 13px; margin-bottom: 6px; font-family: monospace; }
  .conf-label { min-width: 70px; color: var(--muted); }
  .conf-bar { height: 14px; background: var(--blue); border-radius: 3px; }
  .conf-pct { min-width: 50px; text-align: right; color: var(--text); }
  .conf-count { min-width: 60px; color: var(--muted); font-size: 12px; }
  .tech-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }
  .tech-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 14px 18px; }
  .tech-card h3 { font-size: 13px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px; }
  .tech-name { color: var(--accent); font-family: monospace; font-size: 14px; font-weight: 600; }
  .tech-rate { color: var(--red); font-weight: 600; font-size: 14px; }
  .tech-example { background: var(--bg); color: var(--muted); font-family: monospace; font-size: 12px; padding: 8px 10px; border-radius: 4px; margin-top: 8px; word-break: break-all; border: 1px solid var(--border); }
  .fix-list { list-style: none; padding: 0; }
  .fix-list li { background: var(--surface); border: 1px solid var(--border); border-left: 3px solid var(--orange); border-radius: 4px; padding: 10px 14px; margin-bottom: 8px; }
  .fix-list .fix-tech { color: var(--accent); font-family: monospace; font-weight: 600; }
  .fix-list .fix-gen { color: var(--muted); font-size: 12px; }
  .fix-list .fix-text { color: var(--text); font-size: 13px; margin-top: 4px; }
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

<div class="exec-summary">
  {% if fails == 0 %}
    Scanner detected <strong>all {{ total }} variants</strong> — no bypass techniques succeeded in this run.
  {% else %}
    Scanner missed <strong>{{ fails }} of {{ total }}</strong> variants ({{ fail_pct }}% evasion rate).
    {% if worst_example %}
    The most effective technique was <strong>{{ worst_example.technique }}</strong> on <strong>{{ worst_example.category }}</strong> payloads &mdash;
    scanner caught {{ worst_example.detected }} but missed {{ worst_example.evaded }}
    ({{ worst_example.evasion_rate }}% evasion).
    Example of a variant that slipped past: <code>{{ worst_example.sample | e }}</code>.
    {% endif %}
  {% endif %}
</div>

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

{% if confidence_total > 0 %}
<div class="chart-wrap">
  <div class="chart-label">Confidence distribution (detected matches — {{ confidence_total }} rows)</div>
  {% for row in confidence_rows %}
  <div class="conf-row">
    <span class="conf-label">{{ row.label }}</span>
    <span class="conf-bar" style="width: {{ row.width }}px"></span>
    <span class="conf-pct">{{ row.pct }}%</span>
    <span class="conf-count">({{ row.count }})</span>
  </div>
  {% endfor %}
</div>
{% endif %}

{% if worst_techniques %}
<h2>Top evading techniques</h2>
<div class="tech-grid">
  {% for t in worst_techniques %}
  <div class="tech-card">
    <h3>{{ t.category_label }}</h3>
    <div><span class="tech-name">{{ t.technique }}</span> &mdash; <span class="tech-rate">{{ t.evasion_rate }}% evasion</span></div>
    <div style="color: var(--muted); font-size: 12px; margin-top: 4px;">
      {{ t.evaded }} evaded / {{ t.total }} tested
    </div>
    {% if t.example %}
    <div class="tech-example">{{ t.example | e }}</div>
    {% endif %}
  </div>
  {% endfor %}
</div>
{% endif %}

{% if suggestions %}
<h2>What to fix (Siphon rule suggestions)</h2>
<ul class="fix-list">
  {% for s in suggestions %}
  <li>
    <span class="fix-tech">{{ s.technique }}</span>
    <span class="fix-gen">({{ s.generator }})</span>
    <div class="fix-text">{{ s.suggested_fix }}</div>
  </li>
  {% endfor %}
</ul>
{% endif %}

<h2>All variant results</h2>
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
  <td class="variant-cell" title="{{ r.variant.value | e }}">{{ r.variant.value[:60] | e }}{% if r.variant.value | length > 60 %}&hellip;{% endif %}</td>
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


_CONFIDENCE_BUCKETS = [
    ("0.9-1.0", 0.9, 1.01),
    ("0.7-0.9", 0.7, 0.9),
    ("0.5-0.7", 0.5, 0.7),
    ("0.3-0.5", 0.3, 0.5),
    ("0.0-0.3", 0.0, 0.3),
]


def _confidence_rows(results):
    counts = {label: 0 for label, _lo, _hi in _CONFIDENCE_BUCKETS}
    total = 0
    for r in results:
        if not r.detected or r.confidence is None:
            continue
        try:
            c = float(r.confidence)
        except (TypeError, ValueError):
            continue
        total += 1
        for label, lo, hi in _CONFIDENCE_BUCKETS:
            if lo <= c < hi:
                counts[label] += 1
                break
    rows = []
    if total == 0:
        return rows, 0
    for label, _lo, _hi in _CONFIDENCE_BUCKETS:
        n = counts[label]
        pct = round(n / total * 100, 1)
        rows.append({
            "label": label,
            "count": n,
            "pct": pct,
            "width": int(round(pct * 3)),  # 1% = 3px, max 300px
        })
    return rows, total


def _worst_techniques(results, limit: int = 4):
    """Rank (category, technique) pairs by evasion rate with sample output."""
    buckets: dict = defaultdict(lambda: {"pass": 0, "fail": 0, "sample": None})
    for r in results:
        if r.severity == SeverityLevel.ERROR:
            continue
        key = (r.payload.category.value, r.variant.technique or r.variant.generator)
        buckets[key][r.severity.value] += 1
        if r.severity == SeverityLevel.FAIL and buckets[key]["sample"] is None:
            buckets[key]["sample"] = r.variant.value
    rows = []
    for (cat, tech), counts in buckets.items():
        total = counts["pass"] + counts["fail"]
        if total < 3 or counts["fail"] == 0:
            continue
        rate = round(counts["fail"] / total * 100, 1)
        rows.append({
            "category_label": cat.replace("_", " ").title(),
            "technique": tech,
            "evasion_rate": rate,
            "evaded": counts["fail"],
            "total": total,
            "example": (counts["sample"] or "")[:180],
        })
    rows.sort(key=lambda x: -x["evasion_rate"])
    return rows[:limit]


def _worst_example(results):
    """Single worst (category, technique) pair, used in the exec summary."""
    rows = _worst_techniques(results, limit=1)
    if not rows:
        return None
    r = rows[0]
    return {
        "technique": r["technique"],
        "category": r["category_label"],
        "evaded": r["evaded"],
        "detected": r["total"] - r["evaded"],
        "evasion_rate": r["evasion_rate"],
        "sample": r["example"],
    }


class HtmlReporter(BaseReporter):
    def render(self, results: list[ScanResult]) -> str:
        total  = len(results)
        passes = sum(1 for r in results if r.severity == SeverityLevel.PASS)
        fails  = sum(1 for r in results if r.severity == SeverityLevel.FAIL)
        errors = sum(1 for r in results if r.severity == SeverityLevel.ERROR)

        pass_pct  = round(passes / total * 100, 1) if total else 0
        fail_pct  = round(fails  / total * 100, 1) if total else 0
        error_pct = round(errors / total * 100, 1) if total else 0

        conf_rows, conf_total = _confidence_rows(results)
        worst_techs = _worst_techniques(results, limit=6)
        worst_ex = _worst_example(results)

        try:
            suggestions = get_suggestions(results)
        except Exception:
            suggestions = []

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
            confidence_rows=conf_rows,
            confidence_total=conf_total,
            worst_techniques=worst_techs,
            worst_example=worst_ex,
            suggestions=suggestions,
        )
