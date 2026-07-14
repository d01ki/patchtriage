"""Run the triage pipeline for one registered target and summarize it."""

from __future__ import annotations

import json
import os
import time
from importlib import resources

from ..context import apply_context, load_inventory  # noqa: F401 (parity)
from ..dedup import dedup
from ..enrich.clients import enrich, enrich_from_snapshot
from ..evalcmp import evaluate
from ..ingest.parsers import load_file
from ..models import Asset
from ..plan import build_plan, finding_risk, risk_factors
from ..report.html import render_html
from ..triage.audit import audit_all
from ..triage.engine import get_backend, run_triage
from .. import targets as tstore


def run_target(target: dict, backend: str = "rules", use_nvd: bool = False,
               nvd_api_key: str | None = None,
               vendor_sources: str | None = "auto") -> dict:
    """Ingest -> enrich -> triage -> plan -> report for one target.

    Returns a summary dict and writes the target's HTML report to disk.
    Raises ValueError if the target has no attached scan/SBOM.
    """
    started = time.perf_counter()
    source = target.get("source_file")
    if not source:
        raise ValueError("no scan or SBOM attached to this target")

    override = Asset(
        identifier=target["name"],
        kind="sbom" if target.get("source_format") in ("cyclonedx", "spdx") else "host",
        criticality=target.get("criticality", "unknown"),
        internet_exposed=bool(target.get("internet_exposed")),
        reachable=target.get("reachable"),
        runtime_observed=target.get("runtime_observed"),
        context_sources=target.get("context_sources") or [],
    )
    raw = load_file(source, asset=override)
    findings = dedup(raw)
    if target.get("demo"):
        data = resources.files("patchtriage") / "data"
        snapshots = {
            name: json.loads((data / f"demo_{name}.json").read_text(encoding="utf-8"))
            for name in ("epss", "kev", "nvd")
        }
        enrich_from_snapshot(findings, **snapshots)
    else:
        enrich(
            findings, nvd_api_key=nvd_api_key, use_nvd=use_nvd,
            vendor_sources=vendor_sources,
            github_token=(os.environ.get("GITHUB_TOKEN") or
                          os.environ.get("GH_TOKEN")),
        )

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
    top_candidates = [
        f for f in findings if top and f.key in top.finding_keys]
    top_finding = max(top_candidates, key=finding_risk) if top_candidates else None
    explanation = None
    if top_finding:
        e = top_finding.enrichment
        explanation = {
            "vuln_id": top_finding.vuln_id,
            "package": top_finding.package.name,
            "cvss": e.nvd_cvss_score or top_finding.cvss_score,
            "epss": e.epss_score,
            "kev": e.in_cisa_kev,
            "ransomware": e.kev_ransomware,
            "has_fix": bool(top_finding.package.fixed_version),
            "factors": risk_factors(top_finding),
            "advisories": [
                advisory.model_dump(mode="json")
                for advisory in e.vendor_advisories[:5]
            ],
        }
    comparison = None
    if eval_rows:
        row = eval_rows[0]
        comparison = {
            "k": row.k,
            "kev_total": row.kev_total,
            "kev": {
                "cvss": row.kev_baseline,
                "epss": row.kev_epss,
                "patchtriage": row.kev_patchtriage,
            },
            "epss_mass": {
                "cvss": row.epss_baseline,
                "epss": row.epss_epss,
                "patchtriage": row.epss_patchtriage,
            },
        }

    advisory_keys = {
        (advisory.source, advisory.advisory_id)
        for finding in findings
        for advisory in finding.enrichment.vendor_advisories
    }
    vendor_sources_checked = sorted({
        source for finding in findings
        for source in finding.enrichment.vendor_sources_checked
    })
    vendor_errors = sorted({
        error for finding in findings
        for error in finding.enrichment.vendor_lookup_errors
    })

    return {
        "target_id": target["id"],
        "name": target["name"],
        "url": target.get("url", ""),
        "total": len(findings),
        "counts": counts,
        "kev": kev,
        "vendor_advisories": len(advisory_keys),
        "vendor_sources": vendor_sources_checked,
        "vendor_errors": vendor_errors,
        "actions": len(actions),
        "audit_verified": audit["verified"],
        "audit_flagged": len(audit["flagged"]),
        "audit_rate": round(audit["verified"] / len(findings) * 100, 1)
        if findings else 100.0,
        "risk_reduced": round(sum(a.risk_reduced for a in actions), 3),
        "top_action": (top.summary if top else ""),
        "top_priority": (top.top_priority if top else ""),
        "explanation": explanation,
        "comparison": comparison,
        "demo": bool(target.get("demo")),
        "duration_ms": round((time.perf_counter() - started) * 1000),
        "report_url": f"/report/{target['id']}",
    }
