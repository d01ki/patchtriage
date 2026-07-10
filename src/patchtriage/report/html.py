"""Layer 7 — Reporting.

Generates a single self-contained HTML file (zero external assets, opens
offline) styled as a patch *situation report*: what is burning, what one
action buys you, and the proof that this ordering beats CVSS-sorting.
"""

from __future__ import annotations

import html as _html
from datetime import datetime, timezone

from ..evalcmp import EvalRow
from ..models import Finding
from ..plan import Action, finding_risk

_PRI_COLOR = {"P1": "#B3261E", "P2": "#B26A00", "P3": "#3B5BA5", "P4": "#6B7280"}


def _esc(s) -> str:
    return _html.escape(str(s), quote=True)


def _audit_badge(t: dict) -> str:
    a = t.get("audit")
    if not a:
        return ""
    if a.get("verified"):
        return '<span title="verified against signals" style="color:#1E5B3A;font-weight:700">✓ </span>'
    flags = _esc(", ".join(a.get("flags", [])))
    return (f'<span title="{flags}" style="color:#B26A00;font-weight:700">⚑ </span>')


def render_html(findings: list[Finding], actions: list[Action],
                eval_rows: list[EvalRow] | None = None,
                title: str = "PatchTriage — Situation Report") -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    for f in findings:
        counts[(f.triage or {}).get("priority", "P4")] = \
            counts.get((f.triage or {}).get("priority", "P4"), 0) + 1
    kev_n = sum(1 for f in findings if f.enrichment.in_cisa_kev)
    total = len(findings)

    # segmented priority spine
    spine = ""
    for p in ("P1", "P2", "P3", "P4"):
        w = (counts[p] / total * 100) if total else 0
        if w:
            spine += (f'<div class="seg" style="width:{w:.1f}%;'
                      f'background:{_PRI_COLOR[p]}" title="{p}: {counts[p]}"></div>')

    max_risk = max((a.risk_reduced for a in actions), default=1) or 1
    action_rows = ""
    for i, a in enumerate(actions, 1):
        bar_w = a.risk_reduced / max_risk * 100
        kev_badge = (f'<span class="kev">KEV×{a.kev_count}</span>'
                     if a.kev_count else "")
        action_rows += f"""
        <tr>
          <td class="num">{i}</td>
          <td><span class="pri" style="background:{_PRI_COLOR[a.top_priority]}">{a.top_priority}</span></td>
          <td class="mono">{_esc(a.summary)} {kev_badge}
              <div class="cves">{_esc(", ".join(a.cves[:6]))}{" …" if len(a.cves) > 6 else ""}</div></td>
          <td class="num">{len(a.cves)}</td>
          <td class="num">{a.deadline_days}d</td>
          <td class="riskcell"><div class="riskbar" style="width:{bar_w:.0f}%"></div>
              <span class="riskval">{a.risk_reduced:.2f}</span></td>
        </tr>"""

    finding_rows = ""
    ordered = sorted(findings, key=finding_risk, reverse=True)
    for f in ordered:
        t, e = f.triage or {}, f.enrichment
        p = t.get("priority", "P4")
        finding_rows += f"""
        <tr>
          <td><span class="pri" style="background:{_PRI_COLOR.get(p, '#6B7280')}">{p}</span></td>
          <td class="mono">{_esc(f.vuln_id)}</td>
          <td class="mono">{_esc(f.package.name)} {_esc(f.package.version)}</td>
          <td class="num">{e.nvd_cvss_score or f.cvss_score or "–"}</td>
          <td class="num">{f"{e.epss_score:.3f}" if e.epss_score is not None else "–"}</td>
          <td class="num">{"YES" if e.in_cisa_kev else "–"}</td>
          <td>{_esc(t.get("action", "–"))}</td>
          <td class="mono small">{_esc(f.asset.identifier)}</td>
          <td class="small">{_audit_badge(t)}{_esc((t.get("rationale") or "")[:160])}</td>
        </tr>"""

    eval_html = ""
    if eval_rows:
        body = ""
        for r in eval_rows:
            better = r.kev_patchtriage >= r.kev_baseline
            body += f"""
            <tr><td class="num">top {r.k}</td>
                <td class="num">{r.kev_baseline}/{r.kev_total}</td>
                <td class="num {'win' if better else ''}">{r.kev_patchtriage}/{r.kev_total}</td>
                <td class="num">{r.epss_baseline}</td>
                <td class="num {'win' if r.epss_patchtriage >= r.epss_baseline else ''}">{r.epss_patchtriage}</td></tr>"""
        eval_html = f"""
    <section>
      <h2>Does this beat sorting by CVSS?</h2>
      <p class="lede">Same findings, two orderings, fixed work budget k. Metrics are grounded in
      third-party data (CISA KEV, FIRST EPSS) — the tool cannot grade its own homework.</p>
      <table>
        <thead><tr><th>Budget</th><th>KEV caught — CVSS order</th><th>KEV caught — PatchTriage</th>
        <th>EPSS captured — CVSS order</th><th>EPSS captured — PatchTriage</th></tr></thead>
        <tbody>{body}</tbody>
      </table>
    </section>"""

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(title)}</title>
<style>
  :root {{
    --paper:#F4F6F4; --ink:#19231F; --rule:#C9D2CC; --spruce:#1E3A31;
    --muted:#5C6B63;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--paper); color:var(--ink);
         font:15px/1.55 "Segoe UI", "Helvetica Neue", Arial, sans-serif; }}
  .mono, td.mono {{ font-family:ui-monospace, "SF Mono", Menlo, Consolas, monospace;
                    font-size:13px; }}
  header {{ background:var(--spruce); color:#EDF3EF; padding:28px 40px 22px; }}
  header h1 {{ margin:0; font-size:26px; letter-spacing:.5px; font-weight:600; }}
  header .meta {{ color:#A9C0B4; font-size:13px; margin-top:4px;
                  font-family:ui-monospace, Menlo, monospace; }}
  .spinewrap {{ padding:0 40px; background:var(--spruce); padding-bottom:26px; }}
  .spine {{ display:flex; height:14px; border-radius:3px; overflow:hidden;
            outline:1px solid rgba(255,255,255,.25); }}
  .seg {{ height:100%; }}
  .legend {{ color:#A9C0B4; font-size:12px; margin-top:6px;
             font-family:ui-monospace, Menlo, monospace; }}
  main {{ max-width:1180px; margin:0 auto; padding:30px 40px 60px; }}
  .cards {{ display:flex; gap:14px; flex-wrap:wrap; margin-bottom:8px; }}
  .card {{ background:#fff; border:1px solid var(--rule); border-radius:6px;
           padding:14px 20px; min-width:150px; }}
  .card .v {{ font-size:30px; font-weight:650;
              font-family:ui-monospace, Menlo, monospace; }}
  .card .l {{ font-size:12px; color:var(--muted); text-transform:uppercase;
              letter-spacing:.08em; }}
  h2 {{ font-size:17px; margin:38px 0 6px; letter-spacing:.02em; }}
  .lede {{ color:var(--muted); font-size:13.5px; margin:0 0 14px; max-width:72ch; }}
  table {{ width:100%; border-collapse:collapse; background:#fff;
           border:1px solid var(--rule); border-radius:6px; overflow:hidden; }}
  th {{ text-align:left; font-size:11.5px; text-transform:uppercase;
        letter-spacing:.07em; color:var(--muted); font-weight:600;
        padding:9px 12px; border-bottom:2px solid var(--rule);
        background:#EDF1EE; }}
  td {{ padding:9px 12px; border-bottom:1px solid var(--rule);
        vertical-align:top; }}
  tr:last-child td {{ border-bottom:none; }}
  td.num {{ font-family:ui-monospace, Menlo, monospace; font-size:13px;
            white-space:nowrap; }}
  td.num.win {{ font-weight:700; color:#1E5B3A; }}
  .pri {{ color:#fff; font-family:ui-monospace, Menlo, monospace; font-size:12px;
          font-weight:700; padding:2px 8px; border-radius:3px; display:inline-block; }}
  .kev {{ background:#B3261E; color:#fff; font-size:11px; font-weight:700;
          padding:1px 6px; border-radius:3px; margin-left:6px; }}
  .cves {{ color:var(--muted); font-size:12px; margin-top:3px; }}
  .riskcell {{ min-width:180px; position:relative; }}
  .riskbar {{ height:12px; background:linear-gradient(90deg,#2F5D4A,#1E3A31);
              border-radius:2px; display:inline-block; min-width:2px; }}
  .riskval {{ font-family:ui-monospace, Menlo, monospace; font-size:12px;
              margin-left:8px; color:var(--muted); }}
  .small {{ font-size:12px; color:var(--muted); }}
  footer {{ text-align:center; color:var(--muted); font-size:12px; padding:20px; }}
  @media (max-width:760px) {{ main, header, .spinewrap {{ padding-left:16px; padding-right:16px; }} }}
</style></head>
<body>
<header>
  <h1>{_esc(title)}</h1>
  <div class="meta">generated {now} · {total} findings · {len(actions)} remediation actions · {kev_n} known-exploited (CISA KEV)</div>
</header>
<div class="spinewrap">
  <div class="spine">{spine}</div>
  <div class="legend">P1 {counts['P1']} · P2 {counts['P2']} · P3 {counts['P3']} · P4 {counts['P4']}</div>
</div>
<main>
  <div class="cards">
    <div class="card"><div class="v" style="color:#B3261E">{counts['P1']}</div><div class="l">patch now (P1)</div></div>
    <div class="card"><div class="v">{kev_n}</div><div class="l">exploited in the wild</div></div>
    <div class="card"><div class="v">{len(actions)}</div><div class="l">actions close everything</div></div>
    <div class="card"><div class="v">{total}</div><div class="l">unique findings</div></div>
  </div>

  <section>
    <h2>Remediation plan — highest risk reduced first</h2>
    <p class="lede">One action often closes many findings. Work top-down: each row is a single
    concrete change, sized by how much measured risk it removes.</p>
    <table>
      <thead><tr><th>#</th><th>Pri</th><th>Action</th><th>CVEs</th><th>Due</th><th>Risk reduced</th></tr></thead>
      <tbody>{action_rows}</tbody>
    </table>
  </section>
  {eval_html}
  <section>
    <h2>All findings</h2>
    <table>
      <thead><tr><th>Pri</th><th>CVE</th><th>Package</th><th>CVSS</th><th>EPSS</th>
      <th>KEV</th><th>Action</th><th>Asset</th><th>Rationale</th></tr></thead>
      <tbody>{finding_rows}</tbody>
    </table>
  </section>
</main>
<footer>PatchTriage · signals: FIRST EPSS · CISA KEV · NVD · decisions are auditable against signals</footer>
</body></html>"""
