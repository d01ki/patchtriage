"""Human-facing labels and evidence summaries for triage decisions.

The triage engine deliberately keeps compact machine values (P1-P4).  This
module is the single presentation layer that turns those values into language
an operator can act on without having to know PatchTriage's internals.
"""

from __future__ import annotations

from .evalcmp import EvalRow
from .models import Finding


PRIORITY_DEFINITIONS: dict[str, dict[str, str]] = {
    "P1": {
        "label": "Patch Immediately",
        "description": (
            "Active exploitation or very high near-term likelihood; act now."
        ),
        "window": "3-7 days",
    },
    "P2": {
        "label": "Patch Next",
        "description": (
            "High exploitation likelihood or exposed critical impact; put it "
            "in the next patch window."
        ),
        "window": "14 days",
    },
    "P3": {
        "label": "Schedule Patch",
        "description": (
            "Material severity without stronger exploitation signals; handle "
            "in the normal patch cycle."
        ),
        "window": "30 days",
    },
    "P4": {
        "label": "Monitor / Defer",
        "description": (
            "Lower current risk signals; monitor for change and reassess."
        ),
        "window": "90 days",
    },
}


def priority_definition(priority: str | None) -> dict[str, str]:
    """Return a safe copy of the human definition for a priority code."""
    code = priority if priority in PRIORITY_DEFINITIONS else "P4"
    return {"code": code, **PRIORITY_DEFINITIONS[code]}


def priority_display(priority: str | None) -> str:
    definition = priority_definition(priority)
    return f"{definition['code']} - {definition['label']}"


def priority_evidence(finding: Finding) -> list[dict[str, str]]:
    """Build a compact checklist from the exact signals used by triage.

    ``status`` is intentionally descriptive instead of boolean.  Missing
    telemetry is not the same as evidence that a path is safe.
    """
    enrichment = finding.enrichment
    score = enrichment.nvd_cvss_score or finding.cvss_score
    epss = enrichment.epss_score
    asset_signals = []
    if finding.asset.internet_exposed is True:
        asset_signals.append("internet-exposed")
    if finding.asset.reachable is True:
        asset_signals.append("reachable path")
    if finding.asset.runtime_observed is True:
        asset_signals.append("observed at runtime")

    if enrichment.in_cisa_kev:
        kev_status = "confirmed"
        kev_value = "CISA KEV confirms exploitation in the wild"
        if enrichment.kev_ransomware:
            kev_value += "; ransomware use reported"
    else:
        kev_status = "not-observed"
        kev_value = "Not listed in the loaded CISA KEV data"

    if epss is None:
        epss_status = "unknown"
        epss_value = "FIRST EPSS unavailable"
    elif epss >= 0.5:
        epss_status = "confirmed"
        epss_value = f"EPSS {epss * 100:.1f}% meets the P1 threshold (50%)"
    elif epss >= 0.1:
        epss_status = "confirmed"
        epss_value = f"EPSS {epss * 100:.1f}% meets the P2 threshold (10%)"
    else:
        epss_status = "not-observed"
        epss_value = f"EPSS {epss * 100:.1f}% is below escalation thresholds"

    if asset_signals:
        context_status = "confirmed"
        context_value = ", ".join(asset_signals)
    else:
        context_status = "unknown"
        context_value = "No positive exposure or runtime evidence supplied"

    if score is None:
        impact_status = "unknown"
        impact_value = f"CVSS unavailable; scanner severity is {finding.severity.value}"
    else:
        impact_status = "confirmed" if score >= 7.0 else "not-observed"
        impact_value = f"CVSS {score:g}" + (
            " meets the high-impact threshold" if score >= 7.0
            else " is below the high-impact threshold"
        )

    has_fix = bool(finding.package.fixed_version)
    return [
        {"label": "Known exploitation", "status": kev_status,
         "value": kev_value},
        {"label": "Exploit likelihood", "status": epss_status,
         "value": epss_value},
        {"label": "Operational exposure", "status": context_status,
         "value": context_value},
        {"label": "Impact", "status": impact_status,
         "value": impact_value},
        {"label": "Fix readiness", "status": "confirmed" if has_fix else "attention",
         "value": (f"Fixed version {finding.package.fixed_version} is available"
                   if has_fix else "No fixed version supplied; mitigate or investigate")},
    ]


def priority_basis(finding: Finding) -> str:
    """Explain the strongest deterministic reason for the assigned priority."""
    triage = finding.triage or {}
    priority = triage.get("priority", "P4")
    enrichment = finding.enrichment
    epss = enrichment.epss_score or 0.0
    contextual = any((
        finding.asset.internet_exposed is True,
        finding.asset.reachable is True,
        finding.asset.runtime_observed is True,
    ))
    score = enrichment.nvd_cvss_score or finding.cvss_score or 0.0

    if priority == "P1" and enrichment.in_cisa_kev:
        return "P1 because CISA KEV confirms this vulnerability is exploited in the wild."
    if priority == "P1" and epss >= 0.5 and contextual:
        return (
            f"P1 because EPSS is {epss * 100:.1f}% and the asset has positive "
            "exposure or runtime evidence."
        )
    if priority == "P2" and epss >= 0.1:
        return f"P2 because EPSS is {epss * 100:.1f}%, above the 10% escalation threshold."
    if priority == "P2" and score >= 9.0 and contextual:
        return "P2 because critical impact is combined with exposure or runtime relevance."
    if priority == "P3" and score >= 7.0:
        return f"P3 because CVSS {score:g} indicates high impact without a stronger P1/P2 trigger."
    return (
        f"{priority} reflects the loaded exploitation, impact, and asset-context "
        "signals; the checklist below shows each input."
    )


def evaluation_outcome(row: EvalRow, total_findings: int) -> dict[str, float | int | None]:
    """Translate one evaluation row into user-facing outcome measures."""
    reviewed = min(row.k, total_findings)
    review_reduction = (
        (1 - reviewed / total_findings) * 100 if total_findings else 0.0
    )
    patchtriage_coverage = (
        row.kev_patchtriage / row.kev_total * 100 if row.kev_total else 0.0
    )
    cvss_coverage = (
        row.kev_baseline / row.kev_total * 100 if row.kev_total else 0.0
    )
    return {
        "reviewed": reviewed,
        "review_reduction_pct": round(review_reduction, 1),
        "kev_coverage_pct": round(patchtriage_coverage, 1),
        "kev_gain_points": round(patchtriage_coverage - cvss_coverage, 1),
        "additional_kev_vs_cvss": row.kev_patchtriage - row.kev_baseline,
        "kev_lift_vs_cvss": (
            round(row.kev_patchtriage / row.kev_baseline, 1)
            if row.kev_baseline else None
        ),
    }
