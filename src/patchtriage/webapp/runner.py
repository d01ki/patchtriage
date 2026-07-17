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
from ..plan import build_plan
from ..presentation import (
    evaluation_outcome,
    priority_basis,
    priority_definition,
    priority_evidence,
)
from ..report.html import render_html
from ..ssvc import ssvc_order_key
from ..triage.audit import audit_all
from ..triage.engine import get_backend, run_triage
from .. import targets as tstore


def asset_from_target(target: dict) -> Asset:
    """Build the exact asset context consumed by the SSVC engine.

    Keeping this conversion pure makes it possible to verify that values
    entered in the GUI reach the decision engine unchanged. Automatable is a
    vulnerability-specific SSVC point, so the web target never applies one
    value to every finding; the engine derives it per vulnerability instead.
    """
    return Asset(
        identifier=target["name"],
        kind="sbom" if target.get("source_format") in ("cyclonedx", "spdx") else "host",
        criticality=target.get("criticality", "unknown"),
        internet_exposed=target.get("internet_exposed"),
        reachable=target.get("reachable"),
        runtime_observed=target.get("runtime_observed"),
        system_exposure=target.get("system_exposure", "unknown"),
        automatable="unknown",
        mission_impact=target.get("mission_impact", "unknown"),
        safety_impact=target.get("safety_impact", "unknown"),
        context_sources=target.get("context_sources") or [],
    )


def run_target(target: dict, backend: str = "rules", use_nvd: bool = False,
               nvd_api_key: str | None = None,
               vendor_sources: str | None = "auto",
               workspace_id: str | None = None) -> dict:
    """Ingest -> enrich -> triage -> plan -> report for one target.

    Returns a summary dict and writes the target's HTML report to disk.
    Raises ValueError if the target has no attached scan/SBOM.
    """
    started = time.perf_counter()
    source = target.get("source_file")
    if not source:
        raise ValueError("no scan or SBOM attached to this target")

    override = asset_from_target(target)
    raw = load_file(source, asset=override)
    findings = dedup(raw)
    overrides = target.get("ssvc_overrides") or {}
    for finding in findings:
        values = overrides.get(finding.key)
        if isinstance(values, dict):
            finding.ssvc_inputs = {
                key: str(value)
                for key, value in values.items()
                if key in ("exploitation", "automatable")
            }
    if not findings:
        pass
    elif target.get("demo"):
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
    tstore.report_path(target["id"], workspace_id).write_text(
        html, encoding="utf-8")

    outcomes = {
        "immediate": 0, "out_of_cycle": 0, "scheduled": 0, "defer": 0,
    }
    for f in findings:
        decision = ((f.triage or {}).get("ssvc") or {}).get("decision", "defer")
        outcomes[decision if decision in outcomes else "defer"] += 1
    kev = sum(1 for f in findings if f.enrichment.in_cisa_kev)
    top = actions[0] if actions else None
    top_candidates = [
        f for f in findings if top and f.key in top.finding_keys]
    priority_candidates = [
        f for f in top_candidates
        if (f.triage or {}).get("priority", "P4") == top.top_priority
    ] if top else []
    top_finding_pool = priority_candidates or top_candidates
    top_finding = (
        min(top_finding_pool, key=ssvc_order_key) if top_finding_pool else None
    )
    explanation = None
    if top_finding:
        e = top_finding.enrichment
        priority = (top_finding.triage or {}).get("priority", "P4")
        priority_info = priority_definition(priority)
        ssvc = (top_finding.triage or {}).get("ssvc") or {}
        explanation = {
            "vuln_id": top_finding.vuln_id,
            "package": top_finding.package.name,
            "outcome_label": priority_info["ssvc_outcome"],
            "outcome_description": priority_info["description"],
            "basis": priority_basis(top_finding),
            "checks": priority_evidence(top_finding),
            "rationale": (top_finding.triage or {}).get("rationale", ""),
            "ssvc": ssvc,
            "confidence": ssvc.get("confidence", "low"),
            "needs_confirmation": ssvc.get("needs_confirmation", []),
            "cvss": e.nvd_cvss_score or top_finding.cvss_score,
            "epss": e.epss_score,
            "kev": e.in_cisa_kev,
            "ransomware": e.kev_ransomware,
            "has_fix": bool(top_finding.package.fixed_version),
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
                "kev": row.kev_kev,
                "ssvc": row.kev_ssvc,
                "patchtriage": row.kev_patchtriage,
            },
            "epss_mass": {
                "cvss": row.epss_baseline,
                "epss": row.epss_epss,
                "kev": row.epss_kev,
                "ssvc": row.epss_ssvc,
                "patchtriage": row.epss_patchtriage,
            },
            "urgent": {
                "total": row.urgent_total,
                "cvss": row.urgent_cvss,
                "epss": row.urgent_epss,
                "kev": row.urgent_kev,
                "ssvc": row.urgent_ssvc,
            },
            "outcome": evaluation_outcome(row, len(findings)),
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
    confirmation_fields = sorted({
        field
        for finding in findings
        for field in ((finding.triage or {}).get("ssvc") or {}).get(
            "needs_confirmation", [])
    })
    ssvc_inputs = []
    for finding in findings:
        assessment = ((finding.triage or {}).get("ssvc") or {})
        exploitation = assessment.get("exploitation") or {}
        automatable = assessment.get("automatable") or {}
        ssvc_inputs.append({
            "finding_key": finding.key,
            "vuln_id": finding.vuln_id,
            "package": finding.package.name,
            "exploitation": exploitation,
            "automatable": automatable,
            "override": finding.ssvc_inputs,
            "needs_review": bool(
                exploitation.get("needs_confirmation")
                or automatable.get("needs_confirmation")
            ),
        })

    return {
        "target_id": target["id"],
        "name": target["name"],
        "url": target.get("url", ""),
        "total": len(findings),
        "outcomes": outcomes,
        "kev": kev,
        "vendor_advisories": len(advisory_keys),
        "vendor_sources": vendor_sources_checked,
        "vendor_errors": vendor_errors,
        "actions": len(actions),
        "audit_verified": audit["verified"],
        "audit_flagged": len(audit["flagged"]),
        "audit_rate": round(audit["verified"] / len(findings) * 100, 1)
        if findings else 100.0,
        "top_action": (top.summary if top else ""),
        "top_deadline_days": (top.deadline_days if top else None),
        "top_ssvc_decision": (
            ((top_finding.triage or {}).get("ssvc") or {}).get(
                "decision_label", "") if top_finding else ""
        ),
        "evaluated_context": {
            "system_exposure": override.system_exposure,
            "mission_impact": override.mission_impact,
            "safety_impact": override.safety_impact,
            "context_sources": override.context_sources,
        },
        "result_state": (
            "no_findings" if not findings else
            "assessed" if actions else "no_plan"
        ),
        "result_message": (
            "No vulnerabilities were found in the attached scan or SBOM."
            if not findings else
            "Assessment completed, but no remediation action could be built."
            if not actions else ""
        ),
        "ssvc_confirmation_fields": confirmation_fields,
        "ssvc_inputs": ssvc_inputs,
        "explanation": explanation,
        "comparison": comparison,
        "demo": bool(target.get("demo")),
        "duration_ms": round((time.perf_counter() - started) * 1000),
        "report_url": f"/report/{target['id']}",
    }
