"""Fleet report — one organization-wide patch situation page.

Self-contained HTML (zero external assets) in the same visual language as the
per-target situation report.  It renders the rollup produced by
:func:`patchtriage.fleet.aggregate_fleet` and adds nothing of its own: every
number shown was decided per target by the deterministic SSVC engine.
"""

from __future__ import annotations

import html as _html
from typing import Any

_PRI_COLOR = {"P1": "#DC2626", "P2": "#D97706", "P3": "#2563EB", "P4": "#6B7280"}
_OUTCOME_LABEL = {
    "immediate": ("Immediate", "#DC2626"),
    "out_of_cycle": ("Out-of-Cycle", "#D97706"),
    "scheduled": ("Scheduled", "#2563EB"),
    "defer": ("Defer", "#6B7280"),
}


def _esc(value: Any) -> str:
    return _html.escape(str(value), quote=True)


def _target_state(row: dict) -> str:
    if not row.get("assessed"):
        return '<span style="color:#6B7280">not assessed</span>'
    state = str(row.get("result_state") or "")
    coverage = str(row.get("coverage_status") or "")
    label = _esc(state.replace("_", " ") or "assessed")
    if coverage and coverage != "complete":
        return (f"{label} <span style=\"color:#D97706\" title=\"coverage: "
                f"{_esc(coverage)}\">◐</span>")
    return label


def _queue_rows(queue: list[dict]) -> str:
    if not queue:
        return ("<tr><td colspan='6' style='color:#6B7280'>"
                "No remediation actions yet — run assessments first.</td></tr>")
    rows = []
    for entry in queue:
        pri = str(entry.get("top_priority") or "P4")
        color = _PRI_COLOR.get(pri, "#6B7280")
        outcome = _esc(entry.get("outcome_label") or pri)
        versions = ""
        if entry.get("installed_version") or entry.get("target_version"):
            versions = (f"{_esc(entry.get('installed_version') or '?')} → "
                        f"{_esc(entry.get('target_version') or '?')}")
        kev = int(entry.get("kev_count") or 0)
        kev_cell = (f'<span style="color:#DC2626;font-weight:700">{kev}</span>'
                    if kev else "—")
        rows.append(
            "<tr>"
            f'<td><span style="color:{color};font-weight:700">{outcome}</span>'
            f' <span style="color:#6B7280">({_esc(entry.get("deadline_days"))}d)'
            "</span></td>"
            f"<td>{_esc(entry.get('target_name'))}</td>"
            f"<td><b>{_esc(entry.get('package'))}</b> {versions}</td>"
            f"<td>{_esc(entry.get('summary'))}</td>"
            f"<td style='text-align:right'>{kev_cell}</td>"
            f"<td style='text-align:right'>{_esc(entry.get('finding_count'))}"
            "</td></tr>"
        )
    return "".join(rows)


def _target_rows(targets: list[dict]) -> str:
    rows = []
    for row in targets:
        outcomes = row.get("outcomes") or {}
        chips = " ".join(
            f'<span style="color:{color};font-weight:650">'
            f"{int(outcomes.get(key) or 0)}</span>"
            for key, (_label, color) in _OUTCOME_LABEL.items()
        ) if row.get("assessed") else "—"
        link = (f'<a href="{_esc(row["report_url"])}">report</a>'
                if row.get("report_url") else "")
        rows.append(
            "<tr>"
            f"<td><b>{_esc(row.get('name'))}</b></td>"
            f"<td>{_target_state(row)}</td>"
            f"<td style='text-align:right'>{_esc(row.get('total', '—'))}</td>"
            f"<td>{chips}</td>"
            f"<td style='text-align:right'>{_esc(row.get('kev', '—'))}</td>"
            f"<td>{link}</td></tr>"
        )
    return "".join(rows)


def render_fleet_html(rollup: dict[str, Any],
                      title: str = "PatchTriage — Fleet Report") -> str:
    outcomes = rollup.get("outcomes") or {}
    cards = "".join(
        f'<div class="card"><div class="v" style="color:{color}">'
        f"{int(outcomes.get(key) or 0)}</div><div class='l'>{label}</div></div>"
        for key, (label, color) in _OUTCOME_LABEL.items()
    )
    truncated_note = (
        "<p class='note'>The queue is capped; open per-target reports for the "
        "complete list.</p>" if rollup.get("queue_truncated") else "")
    incomplete = int(rollup.get("coverage_incomplete_targets") or 0)
    coverage_note = (
        f"<p class='note'>◐ {incomplete} target(s) have bounded or "
        "provider-reported evidence coverage; absence of findings there is "
        "not proof of absence.</p>" if incomplete else "")
    unassessed = int(rollup.get("targets_unassessed") or 0)
    unassessed_note = (
        f"<p class='note'>{unassessed} target(s) are imported but not yet "
        "assessed and are excluded from every total above.</p>"
        if unassessed else "")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)}</title>
<style>
  body {{ font: 15px/1.5 system-ui, sans-serif; color:#111827; margin:0;
         background:#F9FAFB; }}
  main {{ max-width: 1080px; margin: 0 auto; padding: 28px 20px 60px; }}
  h1 {{ font-size: 24px; margin: 0 0 4px; }}
  h2 {{ font-size: 17px; margin: 34px 0 10px; }}
  .meta {{ color:#6B7280; margin-bottom: 22px; }}
  .cards {{ display:flex; gap:12px; flex-wrap:wrap; }}
  .card {{ background:#fff; border:1px solid #E5E7EB; border-radius:8px;
           padding:14px 18px; min-width:130px; }}
  .card .v {{ font-size:26px; font-weight:750; }}
  .card .l {{ color:#6B7280; font-size:13px; }}
  table {{ width:100%; border-collapse:collapse; background:#fff;
           border:1px solid #E5E7EB; border-radius:8px; overflow:hidden; }}
  th {{ text-align:left; font-size:12px; text-transform:uppercase;
        letter-spacing:.04em; color:#6B7280; padding:9px 12px;
        border-bottom:1px solid #E5E7EB; background:#F3F4F6; }}
  td {{ padding:9px 12px; border-bottom:1px solid #F3F4F6;
        vertical-align:top; }}
  tr:last-child td {{ border-bottom:none; }}
  .note {{ color:#6B7280; font-size:13px; }}
  a {{ color:#2563EB; }}
</style></head><body><main>
<h1>{_esc(title)}</h1>
<div class="meta">
  {int(rollup.get("targets_assessed") or 0)}/{int(rollup.get("targets_total") or 0)}
  targets assessed · {int(rollup.get("findings_total") or 0)} findings ·
  {int(rollup.get("kev_total") or 0)} on CISA KEV ·
  generated {_esc(rollup.get("generated_at", ""))}
</div>
<div class="cards">{cards}</div>

<h2>Cross-target action queue</h2>
<table>
<tr><th>Outcome</th><th>Target</th><th>Package</th><th>Action</th>
<th>KEV</th><th>Findings</th></tr>
{_queue_rows(rollup.get("queue") or [])}
</table>
{truncated_note}

<h2>Targets</h2>
<table>
<tr><th>Target</th><th>State</th><th>Findings</th>
<th>Imm / OoC / Sched / Defer</th><th>KEV</th><th></th></tr>
{_target_rows(rollup.get("targets") or [])}
</table>
{coverage_note}
{unassessed_note}
</main></body></html>
"""
