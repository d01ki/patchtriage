"""Run the triage pipeline for one registered target and summarize it."""

from __future__ import annotations

from ..context import apply_context, load_inventory  # noqa: F401 (parity)
from ..dedup import dedup
from ..enrich.clients import enrich
from ..evalcmp import evaluate
from ..ingest.parsers import load_file
from ..models import Asset
from ..plan import build_plan
from ..report.html import render_html
from ..triage.audit import audit_all
from ..triage.engine import get_backend, run_triage
from .. import targets as tstore


def run_target(target: dict, backend: str = "rules", use_nvd: bool = False,
               nvd_api_key: str | None = None) -> dict:
    """Ingest -> enrich -> triage -> plan -> report for one target.

    Returns a summary dict and writes the target's HTML report to disk.
    Raises ValueError if the target has no attached scan/SBOM.
    """
    source = target.get("source_file")
    if not source:
        raise ValueError("no scan or SBOM attached to this target")

    override = Asset(
        identifier=target["name"],
        kind="sbom" if target.get("source_format") in ("cyclonedx", "spdx") else "host",
        criticality=target.get("criticality", "unknown"),
        internet_exposed=bool(target.get("internet_exposed")),
    )
    raw = load_file(source, asset=override)
    findings = dedup(raw)
    enrich(findings, nvd_api_key=nvd_api_key, use_nvd=use_nvd)

    be = get_backend(backend)
    run_triage(findings, be, jobs=1 if backend == "rules" else 4)
    audit = audit_all(findings)

    actions = build_plan(findings)
    eval_rows = evaluate(findings)

    title = f"PatchTriage — {target['name']}"
    html = render_html(findings, actions, eval_rows, title=title)
    tstore.report_path(target["id"]).write_text(html, encoding="utf-8")

    counts = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    for f in findings:
        counts[(f.triage or {}).get("priority", "P4")] += 1
    kev = sum(1 for f in findings if f.enrichment.in_cisa_kev)
    top = actions[0] if actions else None

    return {
        "target_id": target["id"],
        "name": target["name"],
        "url": target.get("url", ""),
        "total": len(findings),
        "counts": counts,
        "kev": kev,
        "actions": len(actions),
        "audit_verified": audit["verified"],
        "audit_flagged": len(audit["flagged"]),
        "top_action": (top.summary if top else ""),
        "top_priority": (top.top_priority if top else ""),
        "report_url": f"/report/{target['id']}",
    }
