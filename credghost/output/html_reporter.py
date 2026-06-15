"""Self-contained HTML report.

Produces a single .html file with no external dependencies: inline CSS-only bar
charts, a sortable/filterable table with expandable rows (vanilla JS, no
framework, no CDN), and print-friendly styles so auditors can print to PDF.
"""

from __future__ import annotations

from jinja2 import Environment

from credghost import __version__
from credghost.models.nhi import RiskLevel, ScanResult

_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CredGhost Report — {{ account }}</title>
<style>
  :root {
    --crit:#e5484d; --high:#f76808; --med:#ffb224; --low:#46a758; --info:#8b8d98;
    --bg:#0f1115; --panel:#fff; --ink:#1b1d22; --muted:#6b6f76; --line:#e6e8eb;
  }
  * { box-sizing:border-box; }
  body { margin:0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; color:var(--ink); background:#f4f5f7; }
  header { background:var(--bg); color:#fff; padding:28px 40px; }
  header h1 { margin:0; font-size:22px; letter-spacing:.5px; }
  header .meta { color:#9aa0aa; font-size:13px; margin-top:6px; }
  .wrap { max-width:1180px; margin:0 auto; padding:28px 40px 60px; }
  .cards { display:flex; gap:16px; flex-wrap:wrap; margin:24px 0; }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:18px 22px; flex:1; min-width:150px; }
  .card .n { font-size:30px; font-weight:700; }
  .card .l { color:var(--muted); font-size:13px; margin-top:4px; }
  h2 { font-size:15px; text-transform:uppercase; letter-spacing:1px; color:var(--muted); border-bottom:1px solid var(--line); padding-bottom:8px; margin-top:36px; }
  .bars { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:20px; }
  .bar-row { display:flex; align-items:center; margin:8px 0; font-size:14px; }
  .bar-row .lbl { width:90px; }
  .bar-track { flex:1; background:#eef0f2; border-radius:6px; height:20px; overflow:hidden; }
  .bar-fill { height:100%; border-radius:6px; }
  .bar-row .cnt { width:48px; text-align:right; font-variant-numeric:tabular-nums; }
  .crit{background:var(--crit);} .high{background:var(--high);} .med{background:var(--med);} .low{background:var(--low);} .info{background:var(--info);}
  .pill { display:inline-block; padding:2px 9px; border-radius:999px; font-size:12px; font-weight:600; color:#fff; }
  .pill.crit{background:var(--crit);} .pill.high{background:var(--high);} .pill.med{background:var(--med);} .pill.low{background:var(--low);} .pill.info{background:var(--info);}
  .controls { margin:16px 0; }
  .controls button { border:1px solid var(--line); background:#fff; padding:6px 14px; border-radius:999px; cursor:pointer; font-size:13px; margin-right:6px; }
  .controls button.active { background:var(--ink); color:#fff; border-color:var(--ink); }
  table { width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--line); border-radius:10px; overflow:hidden; }
  th, td { text-align:left; padding:10px 14px; font-size:14px; border-bottom:1px solid var(--line); }
  th { background:#fafbfc; cursor:pointer; user-select:none; white-space:nowrap; }
  th:hover { background:#f0f2f4; }
  tr.detail td { background:#fafbfc; }
  tr.main { cursor:pointer; }
  tr.main:hover { background:#f7f9fb; }
  .perms { display:flex; gap:24px; flex-wrap:wrap; }
  .perms div { flex:1; min-width:220px; }
  .perms h4 { margin:0 0 6px; font-size:12px; text-transform:uppercase; color:var(--muted); }
  .perms ul { margin:0; padding-left:18px; font-size:13px; color:#33363c; max-height:200px; overflow:auto; }
  .reasons { color:var(--muted); font-size:13px; }
  footer { text-align:center; color:var(--muted); font-size:12px; padding:30px; }
  .hidden { display:none; }
  @media print {
    body { background:#fff; }
    .controls, th { cursor:default; }
    .controls button { display:none; }
    tr.detail { display:table-row !important; }
    header { -webkit-print-color-adjust:exact; print-color-adjust:exact; }
    .bar-fill, .pill { -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  }
</style>
</head>
<body>
<header>
  <h1>👻 CredGhost — NHI Security Report</h1>
  <div class="meta">Provider: {{ provider }} &nbsp;•&nbsp; Account: {{ account }} &nbsp;•&nbsp; Scanned: {{ scanned_at }} &nbsp;•&nbsp; {{ duration }}s</div>
</header>
<div class="wrap">

  {% if warnings %}
  <div class="bars" style="border-color:var(--med);">
    {% for w in warnings %}<div>⚠ {{ w }}</div>{% endfor %}
  </div>
  {% endif %}

  <div class="cards">
    <div class="card"><div class="n">{{ summary.total_nhis }}</div><div class="l">Total NHIs</div></div>
    <div class="card"><div class="n">{{ summary.orphaned }}</div><div class="l">Orphaned</div></div>
    <div class="card"><div class="n">{{ summary.stale }}</div><div class="l">Stale &gt;90d</div></div>
    <div class="card"><div class="n">{{ summary.never_used }}</div><div class="l">Never used</div></div>
    <div class="card"><div class="n">{{ summary.over_privileged }}</div><div class="l">Over-privileged</div></div>
  </div>

  <h2>Risk Breakdown</h2>
  <div class="bars">
    {% for level, cls in levels %}
    <div class="bar-row">
      <span class="lbl">{{ level|capitalize }}</span>
      <span class="bar-track"><span class="bar-fill {{ cls }}" style="width: {{ pct(summary.by_risk[level]) }}%"></span></span>
      <span class="cnt">{{ summary.by_risk[level] }}</span>
    </div>
    {% endfor %}
  </div>

  <h2>Identities</h2>
  <div class="controls">
    <button data-filter="all" class="active" onclick="filterRows('all',this)">All</button>
    <button data-filter="critical" onclick="filterRows('critical',this)">Critical</button>
    <button data-filter="high" onclick="filterRows('high',this)">High</button>
    <button data-filter="medium" onclick="filterRows('medium',this)">Medium</button>
    <button data-filter="low" onclick="filterRows('low',this)">Low</button>
    <button data-filter="info" onclick="filterRows('info',this)">Info</button>
  </div>

  <table id="nhi-table">
    <thead>
      <tr>
        <th onclick="sortTable(0)">Identity</th>
        <th onclick="sortTable(1)">Type</th>
        <th onclick="sortTable(2)">Risk</th>
        <th onclick="sortTable(3)">Last Used</th>
        <th onclick="sortTable(4)">Owner</th>
        <th onclick="sortTable(5)">Blast Radius</th>
        <th onclick="sortTable(6)" style="text-align:right">Unused Perms</th>
      </tr>
    </thead>
    <tbody>
      {% for i in identities %}
      <tr class="main" data-risk="{{ i.risk_level.value }}" data-rank="{{ i.risk_level.rank }}" onclick="toggleDetail(this)">
        <td>{{ i.name }}</td>
        <td>{{ i.nhi_type.value.replace('_',' ')|title }}</td>
        <td><span class="pill {{ short(i.risk_level.value) }}">{{ i.risk_level.value|upper }}</span></td>
        <td>{{ i.last_used_display() }}</td>
        <td>{{ i.owner or 'None' }}</td>
        <td>{{ i.blast_radius|capitalize }}</td>
        <td style="text-align:right">{{ i.unused_permissions|length }}</td>
      </tr>
      <tr class="detail hidden" data-risk="{{ i.risk_level.value }}">
        <td colspan="7">
          <div class="reasons"><strong>Risk reasons:</strong> {{ i.risk_reasons|join('; ') or '—' }}</div>
          <div class="reasons"><strong>ID:</strong> {{ i.id }}</div>
          <div class="perms" style="margin-top:12px">
            <div><h4>Granted ({{ i.granted_permissions|length }})</h4><ul>{% for p in i.granted_permissions %}<li>{{ p }}</li>{% endfor %}</ul></div>
            <div><h4>Used ({{ i.used_permissions|length }})</h4><ul>{% for p in i.used_permissions %}<li>{{ p }}</li>{% endfor %}</ul></div>
            <div><h4>Unused ({{ i.unused_permissions|length }})</h4><ul>{% for p in i.unused_permissions %}<li>{{ p }}</li>{% endfor %}</ul></div>
          </div>
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>
<footer>Generated by CredGhost on {{ scanned_at }} — credghost.dev</footer>

<script>
function toggleDetail(row){ var d=row.nextElementSibling; if(d&&d.classList.contains('detail')){ d.classList.toggle('hidden'); } }
function filterRows(level, btn){
  document.querySelectorAll('.controls button').forEach(function(b){ b.classList.remove('active'); });
  btn.classList.add('active');
  document.querySelectorAll('#nhi-table tbody tr').forEach(function(tr){
    var match = (level==='all') || tr.getAttribute('data-risk')===level;
    if(tr.classList.contains('detail')){ tr.classList.add('hidden'); if(match){tr.style.display='';}else{tr.style.display='none';} }
    else { tr.style.display = match ? '' : 'none'; }
  });
}
var sortAsc = {};
function sortTable(col){
  var tbody = document.querySelector('#nhi-table tbody');
  var mains = Array.from(tbody.querySelectorAll('tr.main'));
  sortAsc[col] = !sortAsc[col];
  mains.sort(function(a,b){
    var x, y;
    if(col===2){ x=+a.getAttribute('data-rank'); y=+b.getAttribute('data-rank'); }
    else if(col===6){ x=+a.cells[6].innerText; y=+b.cells[6].innerText; }
    else { x=a.cells[col].innerText.toLowerCase(); y=b.cells[col].innerText.toLowerCase(); }
    if(x<y) return sortAsc[col]?-1:1;
    if(x>y) return sortAsc[col]?1:-1;
    return 0;
  });
  mains.forEach(function(m){ var d=m.nextElementSibling; tbody.appendChild(m); if(d&&d.classList.contains('detail')) tbody.appendChild(d); });
}
</script>
</body>
</html>
"""


def render_html(result: ScanResult) -> str:
    env = Environment(autoescape=True)
    template = env.from_string(_TEMPLATE)

    by_risk = result.by_risk()
    max_count = max(by_risk.values()) or 1

    def pct(value: int) -> int:
        return round(value / max_count * 100)

    short = {
        "critical": "crit",
        "high": "high",
        "medium": "med",
        "low": "low",
        "info": "info",
    }

    # Sort identities worst-first for the table default.
    ordered = sorted(result.identities, key=lambda i: i.risk_level.rank, reverse=True)

    return template.render(
        provider=result.provider,
        account=result.account,
        scanned_at=result.scanned_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        duration=result.scan_duration_seconds,
        summary={
            "total_nhis": result.total_nhis,
            "orphaned": result.orphaned,
            "stale": result.stale,
            "never_used": result.never_used,
            "over_privileged": result.over_privileged,
            "by_risk": by_risk,
        },
        identities=ordered,
        warnings=result.warnings,
        levels=[
            ("critical", "crit"),
            ("high", "high"),
            ("medium", "med"),
            ("low", "low"),
            ("info", "info"),
        ],
        pct=pct,
        short=lambda v: short.get(v, "info"),
        version=__version__,
    )


def write_html(result: ScanResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_html(result))
