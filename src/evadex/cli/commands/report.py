"""evadex report — generate a standalone HTML report from scan JSON.

The output is a single self-contained HTML file — no external CSS,
no external fonts (JetBrains Mono is loaded as a web font from Google
Fonts with a local fallback), no external JS. Designed to be emailed
directly to a CISO, a compliance officer, or an audit partner.

Supports two input shapes:

* A single scan JSON (``evadex scan --format json``) — drives
  Executive Summary, Detection Rate, Per-Category Breakdown, Top
  Evasion Techniques, Recommendations.
* A scan JSON *plus* a false-positive JSON
  (``evadex falsepos --format json``) — adds a False Positive Rate
  section.

Design language
===============

Matches the Siphon C2 palette: phosphor green on a dark slate
background, JetBrains Mono for tabular data, Inter for prose. The
resulting report looks like a single deliverable whether it came from
evadex or from the C2 dashboard.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path

import click
from rich.console import Console

err_console = Console(stderr=True)


# Inline CSS — single-source so the file is portable. Phosphor theme
# borrowed from siphon-c2 with minor adjustments for print.
_CSS = r"""
:root {
  --bg: #0a0e14;
  --bg-elev: #10151d;
  --surface: #141a23;
  --border: #1f2733;
  --text: #d7e0ea;
  --muted: #7a8596;
  --phosphor: #39ff14;
  --phosphor-dim: #1f8f0a;
  --phosphor-bg: rgba(57, 255, 20, 0.08);
  --warn: #ffb93a;
  --warn-bg: rgba(255, 185, 58, 0.10);
  --danger: #ff4757;
  --danger-bg: rgba(255, 71, 87, 0.10);
  --blue: #4ea8ff;
  --accent: #8affc1;
  --mono: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', ui-monospace, Consolas, monospace;
  --sans: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
html, body { background: var(--bg); color: var(--text); font-family: var(--sans); font-size: 14.5px; line-height: 1.55; }
body { padding: 32px; max-width: 1180px; margin: 0 auto; }
header { border-bottom: 1px solid var(--border); padding-bottom: 24px; margin-bottom: 32px; display: flex; justify-content: space-between; align-items: flex-end; }
h1 { font-family: var(--mono); font-size: 22px; color: var(--phosphor); letter-spacing: 0.06em; text-transform: uppercase; font-weight: 600; }
h1::before { content: "> "; color: var(--phosphor-dim); }
h2 { font-family: var(--mono); font-size: 14px; color: var(--phosphor); text-transform: uppercase; letter-spacing: 0.1em; margin: 32px 0 14px; padding-bottom: 6px; border-bottom: 1px solid var(--border); }
h2::before { content: "## "; color: var(--phosphor-dim); }
h3 { font-size: 15px; color: var(--accent); margin: 20px 0 8px; font-weight: 600; }
p { margin-bottom: 12px; max-width: 80ch; }
.meta { color: var(--muted); font-size: 12px; font-family: var(--mono); }
.meta span { margin-right: 18px; }
.toolbar { display: flex; gap: 8px; }
button, .btn {
  font-family: var(--mono); font-size: 12px; letter-spacing: 0.05em; text-transform: uppercase;
  background: var(--phosphor-bg); color: var(--phosphor); border: 1px solid var(--phosphor-dim);
  padding: 7px 14px; cursor: pointer; border-radius: 3px; transition: all 0.15s ease;
}
button:hover, .btn:hover { background: var(--phosphor); color: var(--bg); }

.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 14px; margin: 20px 0 28px; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 16px 20px; }
.card .lbl { font-family: var(--mono); font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.1em; color: var(--muted); margin-bottom: 6px; }
.card .val { font-family: var(--mono); font-size: 30px; font-weight: 600; color: var(--text); }
.card.good .val { color: var(--phosphor); }
.card.bad  .val { color: var(--danger); }
.card.warn .val { color: var(--warn); }
.card.info .val { color: var(--blue); }

.summary { background: var(--bg-elev); border-left: 3px solid var(--phosphor); padding: 16px 20px; border-radius: 3px; font-size: 15px; line-height: 1.65; }
.summary strong { color: var(--phosphor); }

table { width: 100%; border-collapse: collapse; background: var(--surface); border: 1px solid var(--border); border-radius: 6px; overflow: hidden; margin-bottom: 20px; }
thead th { background: var(--bg-elev); text-align: left; font-family: var(--mono); font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); padding: 10px 14px; border-bottom: 1px solid var(--border); font-weight: 600; }
tbody td { padding: 9px 14px; border-bottom: 1px solid var(--border); font-size: 13.5px; }
tbody tr:last-child td { border-bottom: none; }
tbody tr:hover td { background: rgba(255,255,255,0.025); }
.num  { font-family: var(--mono); text-align: right; }
.mono { font-family: var(--mono); }

.bar-track { height: 10px; background: var(--border); border-radius: 2px; overflow: hidden; display: inline-block; width: 160px; vertical-align: middle; }
.bar-fill { height: 100%; background: var(--phosphor); border-radius: 2px; }
.bar-fill.warn { background: var(--warn); }
.bar-fill.bad  { background: var(--danger); }

.rec-list { list-style: none; }
.rec-list li { background: var(--surface); border: 1px solid var(--border); border-left: 3px solid var(--phosphor); border-radius: 3px; padding: 12px 16px; margin-bottom: 10px; }
.rec-list li.warn { border-left-color: var(--warn); }
.rec-list li.bad  { border-left-color: var(--danger); }
.rec-list li strong { color: var(--phosphor); font-family: var(--mono); font-size: 12.5px; text-transform: uppercase; letter-spacing: 0.06em; }

footer { margin-top: 48px; padding-top: 16px; border-top: 1px solid var(--border); color: var(--muted); font-size: 11.5px; font-family: var(--mono); }

@media print {
  body { background: white; color: black; padding: 16px; }
  h1, h2, h3 { color: black; }
  .card, table, .summary, .rec-list li { background: white; border-color: #ccc; }
  button { display: none; }
}
""".strip()


# The "Export JSON" button is the only bit of JS — it reads an embedded
# base64 blob and triggers a download. No external dependency.
_JS = r"""
(function() {
  const btn = document.getElementById('export-json');
  if (!btn) return;
  btn.addEventListener('click', function() {
    const blob = window.__evadexRawJson;
    if (!blob) { alert('No raw data attached.'); return; }
    const decoded = atob(blob);
    const a = document.createElement('a');
    a.href = 'data:application/json;base64,' + blob;
    a.download = 'evadex-report.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  });
})();
""".strip()


def _load_json(path: Path) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        err_console.print(
            f"[red]Cannot parse '{path}': invalid JSON "
            f"({exc.msg} at line {exc.lineno}, column {exc.colno}).[/red]"
        )
        raise SystemExit(1) from None
    except OSError as exc:
        err_console.print(
            f"[red]Cannot read '{path}': {exc.strerror}.[/red]"
        )
        raise SystemExit(1) from None


def _is_scan_json(doc: dict) -> bool:
    """Heuristic — scan JSON carries ``meta.total`` and ``results``."""
    return (
        "meta" in doc
        and isinstance(doc.get("results"), list)
        and "pass" in doc.get("meta", {})
    )


def _is_falsepos_json(doc: dict) -> bool:
    return "overall_false_positive_rate" in doc and "by_category" in doc


def _pct(n: int, d: int) -> float:
    return round(n / d * 100, 1) if d else 0.0


def _escape(s: object) -> str:
    """Minimal HTML escape. Kept local to avoid an html.parser import."""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _executive_summary(scan: dict, falsepos: dict | None) -> str:
    meta = scan["meta"]
    total = meta["total"]
    fails = meta["fail"]
    detection = meta.get("pass_rate", 0.0)
    scanner = meta.get("scanner", "unknown scanner")

    pieces: list[str] = []
    pieces.append(
        f"This report summarises a DLP evasion test against "
        f"<strong>{_escape(scanner)}</strong>. evadex generated "
        f"<strong>{total:,}</strong> evasion variants across every "
        f"category in the selected tier and observed how the scanner "
        f"responded."
    )

    if detection >= 95:
        pieces.append(
            f"The scanner caught <strong>{detection}%</strong> of the "
            f"test cases — a strong baseline. The remaining "
            f"<strong>{fails:,}</strong> variant(s) represent residual "
            f"risk worth investigating, but overall coverage is "
            f"enterprise-grade."
        )
    elif detection >= 70:
        pieces.append(
            f"The scanner caught <strong>{detection}%</strong> of the "
            f"test cases and missed <strong>{fails:,}</strong>. Coverage "
            f"is workable but not complete — the categories and "
            f"techniques below highlight where additional rules would "
            f"move the needle most."
        )
    else:
        pieces.append(
            f"The scanner caught only <strong>{detection}%</strong> of "
            f"the test cases, missing <strong>{fails:,}</strong> "
            f"variants. This is a material gap. We recommend prioritising "
            f"the top techniques and categories below for detection-rule "
            f"work before production roll-out."
        )

    if falsepos is not None:
        fp = falsepos.get("overall_false_positive_rate", 0.0)
        total_fp = falsepos.get("total_tested", 0)
        flagged = falsepos.get("total_flagged", 0)
        if fp >= 10:
            pieces.append(
                f"A separate false-positive run tested "
                f"<strong>{total_fp:,}</strong> random synthetic values "
                f"and the scanner flagged <strong>{flagged:,}</strong> "
                f"({fp}%) — a high rate that will generate operational "
                f"noise. Tuning thresholds or keyword-proximity rules "
                f"should be part of the detection-rule work."
            )
        else:
            pieces.append(
                f"False-positive testing flagged <strong>{flagged:,}</strong> "
                f"of <strong>{total_fp:,}</strong> random synthetic "
                f"values (<strong>{fp}%</strong>), which is within an "
                f"acceptable range for production operation."
            )
    pieces.append(
        "Every finding below can be reproduced by re-running evadex "
        "against the same scanner with the raw JSON attached at the "
        "bottom of this report."
    )
    return "\n".join(f"<p>{p}</p>" for p in pieces)


def _render_cards(scan: dict) -> str:
    meta = scan["meta"]
    total = meta["total"]
    passes = meta["pass"]
    fails = meta["fail"]
    errors = meta.get("error", 0)
    detection = meta.get("pass_rate", 0.0)
    det_class = "good" if detection >= 90 else "warn" if detection >= 70 else "bad"
    return f"""
<div class="cards">
  <div class="card info"><div class="lbl">Variants</div><div class="val">{total:,}</div></div>
  <div class="card good"><div class="lbl">Detected</div><div class="val">{passes:,}</div></div>
  <div class="card bad"><div class="lbl">Evaded</div><div class="val">{fails:,}</div></div>
  <div class="card warn"><div class="lbl">Errors</div><div class="val">{errors:,}</div></div>
  <div class="card {det_class}"><div class="lbl">Detection Rate</div><div class="val">{detection}%</div></div>
</div>
""".strip()


def _bar(pct: float, klass: str = "") -> str:
    return (
        f'<div class="bar-track"><div class="bar-fill {klass}" '
        f'style="width: {max(0.0, min(100.0, pct)):.1f}%"></div></div>'
    )


def _category_table(scan: dict) -> str:
    by_cat = scan["meta"].get("summary_by_category", {})
    rows: list[str] = []
    for cat, c in sorted(by_cat.items()):
        total = c["pass"] + c["fail"] + c.get("error", 0)
        det = _pct(c["pass"], total)
        klass = "" if det >= 90 else ("warn" if det >= 70 else "bad")
        rows.append(
            f"<tr>"
            f"<td class='mono'>{_escape(cat)}</td>"
            f"<td class='num'>{total:,}</td>"
            f"<td class='num'>{c['pass']:,}</td>"
            f"<td class='num'>{c['fail']:,}</td>"
            f"<td>{_bar(det, klass)} <span class='num mono'>{det}%</span></td>"
            f"</tr>"
        )
    return (
        "<table><thead><tr>"
        "<th>Category</th><th class='num'>Tested</th>"
        "<th class='num'>Detected</th><th class='num'>Evaded</th>"
        "<th>Detection Rate</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _top_techniques(scan: dict, n: int = 15) -> str:
    """Top N techniques by *evaded* count — the ones that need work."""
    by_tech = scan["meta"].get("summary_by_technique", {})
    rows_data: list[tuple[str, int, int, float]] = []
    for tech, c in by_tech.items():
        total = c["pass"] + c["fail"] + c.get("error", 0)
        if total == 0:
            continue
        evasion = _pct(c["fail"], total)
        rows_data.append((tech, c["fail"], total, evasion))
    rows_data.sort(key=lambda t: (-t[1], -t[3]))
    rows: list[str] = []
    for tech, fails, total, evasion in rows_data[:n]:
        klass = "bad" if evasion >= 50 else ("warn" if evasion >= 20 else "")
        rows.append(
            f"<tr><td class='mono'>{_escape(tech)}</td>"
            f"<td class='num'>{fails:,}</td>"
            f"<td class='num'>{total:,}</td>"
            f"<td>{_bar(evasion, klass)} <span class='num mono'>{evasion}%</span></td></tr>"
        )
    if not rows:
        return "<p class='meta'>No technique data in this scan.</p>"
    return (
        "<table><thead><tr>"
        "<th>Technique</th><th class='num'>Evaded</th>"
        "<th class='num'>Tested</th><th>Evasion Rate</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _falsepos_section(fp: dict) -> str:
    rate = fp.get("overall_false_positive_rate", 0.0)
    total = fp.get("total_tested", 0)
    flagged = fp.get("total_flagged", 0)
    klass = "good" if rate < 5 else ("warn" if rate < 15 else "bad")
    cards = f"""
<div class="cards">
  <div class="card info"><div class="lbl">Synthetic tested</div><div class="val">{total:,}</div></div>
  <div class="card warn"><div class="lbl">Flagged (FP)</div><div class="val">{flagged:,}</div></div>
  <div class="card {klass}"><div class="lbl">False-Positive Rate</div><div class="val">{rate}%</div></div>
</div>
""".strip()
    rows: list[str] = []
    by_cat = fp.get("by_category", {})
    for cat, c in sorted(by_cat.items()):
        r = c.get("false_positive_rate", 0.0)
        kl = "" if r < 5 else ("warn" if r < 20 else "bad")
        rows.append(
            f"<tr><td class='mono'>{_escape(cat)}</td>"
            f"<td class='num'>{c.get('total', 0):,}</td>"
            f"<td class='num'>{c.get('flagged', 0):,}</td>"
            f"<td>{_bar(r, kl)} <span class='num mono'>{r}%</span></td></tr>"
        )
    table = (
        "<table><thead><tr><th>Category</th>"
        "<th class='num'>Tested</th><th class='num'>Flagged</th>"
        "<th>FP Rate</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )
    return cards + table


def _recommendations(scan: dict, fp: dict | None) -> str:
    """Plain-English, actionable bullets. Derived from the data."""
    recs: list[tuple[str, str, str]] = []
    meta = scan["meta"]
    detection = meta.get("pass_rate", 0.0)

    # Category-level
    by_cat = meta.get("summary_by_category", {})
    weak_cats = []
    for cat, c in by_cat.items():
        total = c["pass"] + c["fail"] + c.get("error", 0)
        if total and _pct(c["pass"], total) < 50:
            weak_cats.append((cat, _pct(c["pass"], total)))
    weak_cats.sort(key=lambda t: t[1])
    if weak_cats:
        top = ", ".join(f"{c} ({p}%)" for c, p in weak_cats[:5])
        recs.append((
            "Prioritise detection rules for weak categories",
            f"The following categories detected under 50 %: {top}. "
            f"Adding pattern or keyword-proximity rules here will give "
            f"the biggest coverage lift per engineering hour.",
            "bad" if weak_cats[0][1] < 20 else "warn",
        ))

    # Technique-level. Apply a minimum-sample floor so single-sample
    # "100 % evasion" techniques (which are statistical noise under
    # --evasion-mode weighted / random) don't get surfaced to a CISO as
    # bypass patterns. 10 samples roughly matches the smallest category
    # used by the morse_* techniques and excludes the 1-sample flukes.
    _MIN_SAMPLES = 10
    by_tech = meta.get("summary_by_technique", {})
    evading_tech = []
    for tech, c in by_tech.items():
        total = c["pass"] + c["fail"] + c.get("error", 0)
        if total >= _MIN_SAMPLES and _pct(c["fail"], total) >= 75:
            evading_tech.append((tech, _pct(c["fail"], total), total))
    # Sort by rate, then by sample count — ties broken by more-tested wins.
    evading_tech.sort(key=lambda t: (-t[1], -t[2]))
    if evading_tech:
        top = ", ".join(f"{t} ({p}%, n={n})" for t, p, n in evading_tech[:5])
        recs.append((
            "Address the top evasion techniques",
            f"These techniques bypassed detection ≥ 75 % of the time "
            f"(minimum {_MIN_SAMPLES} samples): {top}. Most are solved "
            f"by NFKC-normalising input before regex matching and by "
            f"decoding nested encodings two layers deep.",
            "warn",
        ))

    if detection >= 95 and not evading_tech:
        recs.append((
            "Maintain current baseline",
            "Detection is strong across categories and techniques. "
            "Re-run this report after scanner rule changes to confirm "
            "no regressions.",
            "good",
        ))

    if fp is not None:
        rate = fp.get("overall_false_positive_rate", 0.0)
        if rate >= 15:
            recs.append((
                "Reduce false-positive noise",
                f"The scanner flagged {rate}% of random synthetic "
                f"values. Tightening keyword-proximity thresholds or "
                f"adding negative-lookahead anchors in the top-offending "
                f"categories will reduce operational noise without "
                f"hurting evasion detection.",
                "warn" if rate < 25 else "bad",
            ))

    if not recs:
        recs.append((
            "Nothing critical",
            "No material issues were identified. Schedule a re-run "
            "whenever the scanner ruleset is updated.",
            "good",
        ))

    items = "".join(
        f'<li class="{cls}"><strong>{_escape(title)}</strong><br>{_escape(body)}</li>'
        for (title, body, cls) in recs
    )
    return f'<ul class="rec-list">{items}</ul>'


def _render_html(scan: dict, falsepos: dict | None, raw_combined: dict) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    meta = scan["meta"]
    scanner = _escape(meta.get("scanner", "unknown"))
    generated_at = _escape(meta.get("timestamp", timestamp))
    raw_b64 = base64.b64encode(
        json.dumps(raw_combined, indent=2, ensure_ascii=False).encode("utf-8")
    ).decode("ascii")

    fp_section = ""
    if falsepos is not None:
        fp_section = (
            '<h2>False Positive Rate</h2>'
            + _falsepos_section(falsepos)
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>evadex DLP Report — {scanner}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>{_CSS}</style>
</head>
<body>
<header>
  <div>
    <h1>evadex DLP Report</h1>
    <div class="meta">
      <span>Scanner: {scanner}</span>
      <span>Generated: {generated_at}</span>
      <span>Report rendered: {timestamp}</span>
    </div>
  </div>
  <div class="toolbar">
    <button id="export-json">Export JSON</button>
  </div>
</header>

<h2>Executive Summary</h2>
<div class="summary">
{_executive_summary(scan, falsepos)}
</div>

<h2>Detection Rate</h2>
{_render_cards(scan)}

<h2>Per-Category Breakdown</h2>
{_category_table(scan)}

<h2>Top Evasion Techniques</h2>
{_top_techniques(scan)}

{fp_section}

<h2>Recommendations</h2>
{_recommendations(scan, falsepos)}

<footer>
Generated by evadex — DLP evasion test suite.
Self-contained report — all data embedded. Click "Export JSON" to download the raw results.
</footer>

<script>
window.__evadexRawJson = "{raw_b64}";
{_JS}
</script>
</body>
</html>
"""


@click.command("report")
@click.argument(
    "inputs",
    nargs=-1,
    required=True,
    type=click.Path(exists=True, dir_okay=False),
)
@click.option(
    "--output", "-o",
    required=True,
    type=click.Path(),
    help="Output HTML file path.",
)
def report(inputs: tuple[str, ...], output: str) -> None:
    """Generate a professional HTML report from scan results.

    \b
    The resulting HTML is self-contained — no external CSS, no external
    JS — and suitable for emailing to a CISO or compliance team.

    \b
    Examples:
      evadex report results/scan.json                    # scan results only
      evadex report results/scan.json results/fp.json    # include false positive data
      evadex report results/scan.json --output my_report.html
    """
    scan: dict | None = None
    falsepos: dict | None = None
    raw_combined: dict = {}

    for path in inputs:
        doc = _load_json(Path(path))
        if _is_scan_json(doc):
            scan = doc
            raw_combined["scan"] = doc
        elif _is_falsepos_json(doc):
            falsepos = doc
            raw_combined["falsepos"] = doc
        else:
            err_console.print(
                f"[yellow]Skipping {path}: not recognised as scan or falsepos JSON[/yellow]"
            )

    if scan is None:
        err_console.print(
            "[red]No scan JSON found among inputs — "
            "`evadex report` requires at least one scan result file.[/red]"
        )
        raise SystemExit(1)

    html = _render_html(scan, falsepos, raw_combined)
    out_path = Path(output)
    if not out_path.parent.exists():
        err_console.print(
            f"[red]Cannot write '{output}': parent directory does not exist.[/red]"
        )
        raise SystemExit(1)
    out_path.write_text(html, encoding="utf-8")
    size_kb = out_path.stat().st_size / 1024
    err_console.print(
        f"[green]✓ Report written:[/green] {out_path} "
        f"([dim]{size_kb:.1f} KB[/dim])"
    )
