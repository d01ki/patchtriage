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
from ..plan import Action
from ..presentation import (
    PRIORITY_DEFINITIONS,
    evaluation_outcome,
    priority_basis,
    priority_definition,
    priority_evidence,
)
from ..ssvc import ssvc_order_key

_PRI_COLOR = {"P1": "#DC2626", "P2": "#D97706", "P3": "#2563EB", "P4": "#6B7280"}


def _esc(s) -> str:
    return _html.escape(str(s), quote=True)


def _audit_badge(t: dict) -> str:
    a = t.get("audit")
    if not a:
        return ""
    if a.get("verified"):
        return '<span title="verified against signals" style="color:#2563EB;font-weight:700">✓ </span>'
    flags = _esc(", ".join(a.get("flags", [])))
    return (f'<span title="{flags}" style="color:#D97706;font-weight:700">⚑ </span>')


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
    advisory_keys = {
        (advisory.source, advisory.advisory_id)
        for finding in findings
        for advisory in finding.enrichment.vendor_advisories
    }
    advisory_n = len(advisory_keys)
    vendor_sources = sorted({source for finding in findings
                             for source in finding.enrichment.vendor_sources_checked})
    vendor_errors = sorted({error for finding in findings
                            for error in finding.enrichment.vendor_lookup_errors})

    explain_html = ""
    if actions:
        lead = actions[0]
        candidates = [f for f in findings if f.key in lead.finding_keys]
        priority_candidates = [
            f for f in candidates
            if (f.triage or {}).get("priority", "P4") == lead.top_priority
        ]
        lead_pool = priority_candidates or candidates
        lead_finding = min(lead_pool, key=ssvc_order_key) if lead_pool else None
        if lead_finding:
            priority = (lead_finding.triage or {}).get("priority", "P4")
            priority_info = priority_definition(priority)
            ssvc = (lead_finding.triage or {}).get("ssvc") or {}
            status_icons = {
                "confirmed": "✓", "attention": "!",
                "unknown": "?", "not-observed": "–",
            }
            checks_html = "".join(
                f'<li><span class="checkicon {check["status"]}">'
                f'{status_icons.get(check["status"], "·")}</span><span>'
                f'<b>{_esc(check["label"])}</b><small>{_esc(check["value"])}</small>'
                f'</span></li>'
                for check in priority_evidence(lead_finding)
            )
            decision_points = "".join(
                f'<div class="whynode"><span>{_esc(label)}</span>'
                f'<b>{_esc((ssvc.get(key) or {}).get("label", "Unknown"))}</b>'
                f'<small>{_esc((ssvc.get(key) or {}).get("confidence", "low"))} '
                f'confidence · {_esc((ssvc.get(key) or {}).get("source", "missing"))}'
                f'</small></div>'
                for key, label in (
                    ("exploitation", "Exploitation"),
                    ("system_exposure", "System Exposure"),
                    ("automatable", "Automatable"),
                    ("human_impact", "Human Impact"),
                )
            )
            confirmation = ssvc.get("needs_confirmation") or []
            confirmation_html = (
                '<p class="confirm">Confirm inferred SSVC inputs: '
                f'{_esc(", ".join(value.replace("_", " ") for value in confirmation))}. Conservative defaults remain '
                'active until reviewed.</p>' if confirmation else ""
            )
            explain_html = f"""
    <section>
      <h2>Why {_esc(ssvc.get('decision_label', priority_info['label']))}?</h2>
      <p class="basis">{_esc(priority_basis(lead_finding))}</p>
      <p class="lede">The official SSVC Deployer path is the deployment decision. KEV, EPSS,
      CVSS, reachability, and runtime evidence support its inputs; they do not bypass the tree.</p>
      <div class="whyflow">
        {decision_points}
        <div class="whynode decisionnode"><span>{_esc(ssvc.get('decision_label', priority_info['label']))}</span><b>{_esc(lead.summary)}</b>
          <small>SSVC {_esc(ssvc.get('decision_label', 'Unknown'))} · default SLE ≤ {lead.deadline_days} days</small></div>
      </div>
      {confirmation_html}
      <ul class="evidence">{checks_html}</ul>
    </section>"""

    # segmented priority spine
    spine = ""
    for p in ("P1", "P2", "P3", "P4"):
        w = (counts[p] / total * 100) if total else 0
        if w:
            spine += (f'<div class="seg" style="width:{w:.1f}%;'
                      f'background:{_PRI_COLOR[p]}" title="{_esc(priority_definition(p)["ssvc_outcome"])}: {counts[p]}"></div>')

    action_rows = ""
    for i, a in enumerate(actions, 1):
        kev_badge = (f'<span class="kev">KEV×{a.kev_count}</span>'
                     if a.kev_count else "")
        action_rows += f"""
        <tr>
          <td class="num">{i}</td>
          <td><span class="pri" style="background:{_PRI_COLOR[a.top_priority]}">{_esc(priority_definition(a.top_priority)['ssvc_outcome'])}</span></td>
          <td class="mono">{_esc(a.summary)} {kev_badge}
              <div class="cves">{_esc(", ".join(a.cves[:6]))}{" …" if len(a.cves) > 6 else ""}</div></td>
          <td class="num">{len(a.cves)}</td>
          <td class="num">{a.deadline_days}d</td>
        </tr>"""

    advisory_rows = ""
    advisory_seen = set()
    for finding in findings:
        for advisory in finding.enrichment.vendor_advisories:
            key = (finding.vuln_id, advisory.source, advisory.advisory_id)
            if key in advisory_seen:
                continue
            advisory_seen.add(key)
            label = f"{advisory.source.upper()} · {advisory.advisory_id}"
            advisory_link = (
                f'<a href="{_esc(advisory.url)}" target="_blank" '
                f'rel="noopener">{_esc(label)} ↗</a>'
                if advisory.url.startswith(("https://", "http://"))
                else _esc(label)
            )
            products = ", ".join(advisory.products[:3])
            if len(advisory.products) > 3:
                products += " …"
            fixes = ", ".join(advisory.fixed_versions[:3]) or "—"
            if len(advisory.fixed_versions) > 3:
                fixes += " …"
            advisory_rows += f"""
        <tr>
          <td class="mono">{_esc(finding.vuln_id)}</td>
          <td class="mono">{advisory_link}</td>
          <td>{_esc(advisory.title)}</td>
          <td class="small">{_esc(products or '—')}</td>
          <td class="mono small">{_esc(fixes)}</td>
        </tr>"""

    advisory_html = ""
    if advisory_rows:
        advisory_html = f"""
  <section>
    <h2>Official vendor advisories</h2>
    <p class="lede">Direct evidence from MSRC, Red Hat, Ubuntu, Debian, and
    GitHub. These records explain affected products and fixes; they do not
    inflate the exploitation-likelihood score.</p>
    <table>
      <thead><tr><th>CVE</th><th>Advisory</th><th>Title</th><th>Affected products</th><th>Fixed versions</th></tr></thead>
      <tbody>{advisory_rows}</tbody>
    </table>
  </section>"""

    vendor_error_html = ""
    if vendor_errors:
        items = "".join(f"<li>{_esc(error)}</li>" for error in vendor_errors)
        vendor_error_html = f"""
  <section>
    <h2>Vendor connector warnings</h2>
    <p class="lede">Triage completed using the remaining deterministic
    signals. Retry later to fill these evidence gaps.</p>
    <ul class="warnings">{items}</ul>
  </section>"""

    finding_rows = ""
    ordered = sorted(findings, key=ssvc_order_key)
    for f in ordered:
        t, e = f.triage or {}, f.enrichment
        p = t.get("priority", "P4")
        advisory_badges = []
        for advisory in e.vendor_advisories[:4]:
            label = f"{advisory.source.upper()}:{advisory.advisory_id}"
            if advisory.url.startswith(("https://", "http://")):
                advisory_badges.append(
                    f'<a href="{_esc(advisory.url)}" target="_blank" '
                    f'rel="noopener">{_esc(label)}</a>')
            else:
                advisory_badges.append(_esc(label))
        finding_rows += f"""
        <tr>
          <td><span class="pri" style="background:{_PRI_COLOR.get(p, '#6B7280')}">{_esc(priority_definition(p)['ssvc_outcome'])}</span></td>
          <td class="mono">{_esc(f.vuln_id)}</td>
          <td class="mono">{_esc(f.package.name)} {_esc(f.package.version)}</td>
          <td class="num">{e.nvd_cvss_score or f.cvss_score or "–"}</td>
          <td class="num">{f"{e.epss_score:.3f}" if e.epss_score is not None else "–"}</td>
          <td class="num">{"YES" if e.in_cisa_kev else "—"}</td>
          <td class="mono small">{'<br>'.join(advisory_badges) or '—'}</td>
          <td>{_esc(t.get("action", "—"))}</td>
          <td class="mono small">{_esc(f.asset.identifier)}</td>
          <td class="small">{_audit_badge(t)}{_esc((t.get("rationale") or "")[:160])}</td>
        </tr>"""

    eval_html = ""
    if eval_rows:
        body = ""
        for r in eval_rows:
            best_kev = max(r.kev_baseline, r.kev_epss, r.kev_kev, r.kev_ssvc)
            best_urgent = max(
                r.urgent_cvss, r.urgent_epss, r.urgent_kev, r.urgent_ssvc
            )
            body += f"""
            <tr><td class="num">top {r.k}</td>
                <td class="num {'win' if r.kev_baseline == best_kev else ''}">{r.kev_baseline}/{r.kev_total}</td>
                <td class="num {'win' if r.kev_epss == best_kev else ''}">{r.kev_epss}/{r.kev_total}</td>
                <td class="num {'win' if r.kev_kev == best_kev else ''}">{r.kev_kev}/{r.kev_total}</td>
                <td class="num {'win' if r.kev_ssvc == best_kev else ''}">{r.kev_ssvc}/{r.kev_total}</td>
                <td class="num {'win' if r.urgent_cvss == best_urgent else ''}">{r.urgent_cvss}/{r.urgent_total}</td>
                <td class="num {'win' if r.urgent_epss == best_urgent else ''}">{r.urgent_epss}/{r.urgent_total}</td>
                <td class="num {'win' if r.urgent_kev == best_urgent else ''}">{r.urgent_kev}/{r.urgent_total}</td>
                <td class="num {'win' if r.urgent_ssvc == best_urgent else ''}">{r.urgent_ssvc}/{r.urgent_total}</td></tr>"""
        lead_eval = eval_rows[0]
        outcome = evaluation_outcome(lead_eval, total)
        coverage = (f"{outcome['kev_coverage_pct']:.1f}%"
                    if lead_eval.kev_total else "n/a")
        urgent_coverage = (f"{outcome['urgent_coverage_pct']:.1f}%"
                           if lead_eval.urgent_total else "n/a")
        eval_html = f"""
    <section>
      <h2>Outcome at a top-{lead_eval.k} review budget</h2>
      <div class="outcomecards">
        <div class="outcard"><b>{outcome['review_reduction_pct']:.1f}%</b><span>smaller first-pass queue</span><small>{outcome['reviewed']} of {total} findings reviewed first</small></div>
        <div class="outcard"><b>{coverage}</b><span>known-exploited coverage</span><small>{lead_eval.kev_ssvc} of {lead_eval.kev_total} CISA KEV findings surfaced</small></div>
        <div class="outcard"><b>{urgent_coverage}</b><span>context-urgent coverage</span><small>{lead_eval.urgent_ssvc} of {lead_eval.urgent_total} SSVC Immediate or Out-of-Cycle findings surfaced</small></div>
      </div>
      <h2>What changes when environment context decides?</h2>
      <p class="lede">Same findings and fixed work budget k, compared across CVSS, EPSS,
      KEV-first, and SSVC orderings. CISA KEV is independent observed-exploitation evidence.
      “SSVC urgent” measures coverage of this inventory's Immediate and Out-of-Cycle decisions;
      it is a context-consistency measure, not independent ground truth.</p>
      <table>
        <thead><tr><th>Budget</th><th>KEV · CVSS</th><th>KEV · EPSS</th><th>KEV · KEV-first</th><th>KEV · SSVC</th>
        <th>Urgent · CVSS</th><th>Urgent · EPSS</th><th>Urgent · KEV-first</th><th>Urgent · SSVC</th></tr></thead>
        <tbody>{body}</tbody>
      </table>
    </section>"""

    priority_guide = "".join(
        f'<div class="guideitem"><span class="pri" style="background:{_PRI_COLOR[code]}">'
        f'{_esc(info["ssvc_outcome"])}</span><div>'
        f'<small>{_esc(info["description"])} Typical window: {_esc(info["window"])}.</small>'
        f'</div></div>'
        for code, info in PRIORITY_DEFINITIONS.items()
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(title)}</title>
<style>
  :root {{
    --paper:#F5F6F8; --ink:#1B1F2A; --rule:#DDE1E8; --slate:#1E2430;
    --muted:#5A6472; --accent:#4F46E5;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--paper); color:var(--ink);
         font:15px/1.55 "Segoe UI", "Helvetica Neue", Arial, sans-serif; }}
  .mono, td.mono {{ font-family:ui-monospace, "SF Mono", Menlo, Consolas, monospace;
                    font-size:13px; }}
  header {{ background:var(--slate); color:#EEF1F6; padding:28px 40px 22px; }}
  header h1 {{ margin:0; font-size:26px; letter-spacing:.5px; font-weight:600; }}
  header .meta {{ color:#9AA4B2; font-size:13px; margin-top:4px;
                  font-family:ui-monospace, Menlo, monospace; }}
  .spinewrap {{ padding:0 40px; background:var(--slate); padding-bottom:26px; }}
  .spine {{ display:flex; height:14px; border-radius:3px; overflow:hidden;
            outline:1px solid rgba(255,255,255,.25); }}
  .seg {{ height:100%; }}
  .legend {{ color:#9AA4B2; font-size:12px; margin-top:6px;
             font-family:ui-monospace, Menlo, monospace; }}
  main {{ max-width:1180px; margin:0 auto; padding:30px 40px 60px; }}
  .cards {{ display:flex; gap:14px; flex-wrap:wrap; margin-bottom:8px; }}
  .card {{ background:#fff; border:1px solid var(--rule); border-radius:6px;
           padding:14px 20px; min-width:150px; }}
  .card .v {{ font-size:30px; font-weight:650;
              font-family:ui-monospace, Menlo, monospace; }}
  .card .l {{ font-size:12px; color:var(--muted); text-transform:uppercase;
              letter-spacing:.08em; }}
  .priorityguide {{ display:grid; grid-template-columns:repeat(4,1fr); gap:8px;
                    margin:16px 0 8px; }}
  .guideitem {{ background:#fff; border:1px solid var(--rule); border-radius:6px;
                padding:11px; display:grid; grid-template-columns:auto 1fr; gap:9px;
                align-items:start; }}
  .guideitem b {{ display:block; font-size:12px; }}
  .guideitem small {{ display:block; color:var(--muted); font-size:10.5px;
                      line-height:1.35; margin-top:2px; }}
  h2 {{ font-size:17px; margin:38px 0 6px; letter-spacing:.02em; }}
  .lede {{ color:var(--muted); font-size:13.5px; margin:0 0 14px; max-width:72ch; }}
  table {{ width:100%; border-collapse:collapse; background:#fff;
           border:1px solid var(--rule); border-radius:6px; overflow:hidden; }}
  th {{ text-align:left; font-size:11.5px; text-transform:uppercase;
        letter-spacing:.07em; color:var(--muted); font-weight:600;
        padding:9px 12px; border-bottom:2px solid var(--rule);
        background:#EEF0F4; }}
  td {{ padding:9px 12px; border-bottom:1px solid var(--rule);
        vertical-align:top; }}
  tr:last-child td {{ border-bottom:none; }}
  td.num {{ font-family:ui-monospace, Menlo, monospace; font-size:13px;
            white-space:nowrap; }}
  td.num.win {{ font-weight:700; color:#1D4ED8; }}
  .pri {{ color:#fff; font-family:ui-monospace, Menlo, monospace; font-size:12px;
          font-weight:700; padding:2px 8px; border-radius:3px; display:inline-block; }}
  .prilabel {{ display:block; margin-top:3px; color:var(--muted); font-size:10px;
               font-weight:650; white-space:nowrap; }}
  .kev {{ background:#DC2626; color:#fff; font-size:11px; font-weight:700;
          padding:1px 6px; border-radius:3px; margin-left:6px; }}
  .cves {{ color:var(--muted); font-size:12px; margin-top:3px; }}
  .small {{ font-size:12px; color:var(--muted); }}
  .warnings {{ background:#FFF7ED; border:1px solid #FED7AA; color:#9A3412;
               border-radius:6px; padding:12px 30px; }}
  .basis {{ max-width:84ch; background:#EEF0FF; border-left:4px solid var(--accent);
            color:#293277; border-radius:4px; padding:10px 13px; font-weight:650; }}
  .whyflow {{ display:grid; grid-template-columns:repeat(4,1fr) 1.35fr;
              gap:7px; align-items:stretch; }}
  .whynode {{ background:#fff; border:1px solid var(--rule); border-radius:5px;
              padding:13px 14px; }}
  .whynode span {{ display:block; color:var(--muted); font-size:10px;
                   text-transform:uppercase; letter-spacing:.08em; }}
  .whynode b {{ display:block; margin:5px 0 2px; font-size:13px; }}
  .whynode small {{ color:var(--muted); }}
  .whyop {{ display:flex; align-items:center; justify-content:center; color:#8992A1; }}
  .decisionnode {{ background:#EEF0FF; border-color:#BFC5FF; }}
  .confirm {{ background:#FFF7ED; border:1px solid #FED7AA; color:#9A3412;
              border-radius:5px; padding:9px 12px; font-size:12px; }}
  .evidence {{ list-style:none; padding:0; margin:10px 0 0; display:grid;
               grid-template-columns:repeat(5,1fr); gap:7px; }}
  .evidence li {{ background:#fff; border:1px solid var(--rule); border-radius:5px;
                  padding:9px; display:grid; grid-template-columns:18px 1fr; gap:6px; }}
  .checkicon {{ width:17px; height:17px; border-radius:50%; display:flex;
                align-items:center; justify-content:center; background:#E5E7EB;
                color:#5A6472; font:bold 10px ui-monospace,monospace; }}
  .checkicon.confirmed {{ background:#DCFCE7; color:#166534; }}
  .checkicon.attention {{ background:#FEF3C7; color:#92400E; }}
  .evidence b {{ display:block; font-size:10.5px; }}
  .evidence small {{ display:block; color:var(--muted); font-size:9.5px;
                     line-height:1.35; margin-top:2px; }}
  .outcomecards {{ display:grid; grid-template-columns:repeat(3,1fr); gap:9px;
                   margin:12px 0 20px; }}
  .outcard {{ background:#fff; border:1px solid var(--rule); border-radius:6px;
              padding:14px; }}
  .outcard b {{ display:block; color:#1D4ED8; font:700 25px ui-monospace,monospace; }}
  .outcard span {{ display:block; font-weight:700; font-size:11.5px; }}
  .outcard small {{ color:var(--muted); font-size:10.5px; }}
  footer {{ text-align:center; color:var(--muted); font-size:12px; padding:20px; }}
  @media (max-width:900px) {{ .whyflow {{ grid-template-columns:1fr; }} .whyop {{ transform:rotate(90deg); }} .priorityguide,.evidence {{ grid-template-columns:1fr 1fr; }} }}
  @media (max-width:760px) {{ main, header, .spinewrap {{ padding-left:16px; padding-right:16px; }} }}
  @media (max-width:600px) {{ .priorityguide,.evidence,.outcomecards {{ grid-template-columns:1fr; }} }}
</style></head>
<body>
<header>
  <h1>{_esc(title)}</h1>
  <div class="meta">generated {now} · {total} findings · {len(actions)} remediation actions · {kev_n} known-exploited (CISA KEV)</div>
</header>
<div class="spinewrap">
  <div class="spine">{spine}</div>
  <div class="legend">Immediate {counts['P1']} · Out-of-Cycle {counts['P2']} · Scheduled {counts['P3']} · Defer {counts['P4']}</div>
</div>
<main>
  <div class="cards">
    <div class="card"><div class="v" style="color:#DC2626">{counts['P1']}</div><div class="l">Immediate decisions</div></div>
    <div class="card"><div class="v">{kev_n}</div><div class="l">exploited in the wild</div></div>
    <div class="card"><div class="v">{advisory_n}</div><div class="l">vendor advisories</div></div>
    <div class="card"><div class="v">{len(actions)}</div><div class="l">actions close everything</div></div>
    <div class="card"><div class="v">{total}</div><div class="l">unique findings</div></div>
  </div>
  <div class="priorityguide" aria-label="SSVC outcome meanings">{priority_guide}</div>

  {explain_html}

  <section>
    <h2>Remediation plan — SSVC deployment outcome first</h2>
    <p class="lede">SSVC determines action timing from exploitation, exposure,
    automatable spread, and human impact. One action often closes many findings;
    CVSS and EPSS remain visible as evidence, never as a proprietary score.</p>
    <table>
      <thead><tr><th>#</th><th>SSVC outcome</th><th>Action</th><th>CVEs</th><th>Due</th></tr></thead>
      <tbody>{action_rows}</tbody>
    </table>
  </section>
  {eval_html}
  {advisory_html}
  {vendor_error_html}
  <section>
    <h2>All findings</h2>
    <table>
      <thead><tr><th>SSVC outcome</th><th>CVE</th><th>Package</th><th>CVSS</th><th>EPSS</th>
      <th>KEV</th><th>Vendor evidence</th><th>Action</th><th>Asset</th><th>Rationale</th></tr></thead>
      <tbody>{finding_rows}</tbody>
    </table>
  </section>
</main>
<footer>PatchTriage · decision model: CERT/CC SSVC Deployer · signals: FIRST EPSS · CISA KEV · NVD{_esc(' · ' + ' · '.join(s.upper() for s in vendor_sources) if vendor_sources else '')} · decisions are auditable against the SSVC path</footer>
</body></html>"""
