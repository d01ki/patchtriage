"""Practicality evaluation.

Question to measure: under the same review budget, how do severity-only,
probability-only, observed-exploitation-first, and environment-specific SSVC
orderings differ? SSVC is allowed to place a KEV finding behind a more urgent
deployment decision; the comparison makes that tradeoff visible.

Method: for the same finding set, produce four orderings —
    CVSS baseline: CVSS descending
    EPSS baseline: EPSS descending (the strongest simple alternative)
    KEV baseline : known-exploited first, then EPSS
    SSVC         : Deployer decision, then deterministic context tie-breaker
and compare, at each budget k ("you only have time to fix k findings"):

    KEV@k    — how many known-exploited (CISA KEV) findings are inside top-k
    EPSS@k   — sum of exploitation probability captured inside top-k
    Urgent@k — how many SSVC Immediate / Out-of-Cycle decisions are inside top-k

KEV and EPSS are third-party data (CISA / FIRST). Urgent@k is deliberately
reported as a context-consistency measure, not independent ground truth.
"""

from __future__ import annotations

from pydantic import BaseModel

from .models import Finding
from .ssvc import ssvc_order_key


class EvalRow(BaseModel):
    k: int
    kev_baseline: int
    kev_epss: int
    kev_kev: int
    kev_ssvc: int
    kev_patchtriage: int
    kev_total: int
    epss_baseline: float
    epss_epss: float
    epss_kev: float
    epss_ssvc: float
    epss_patchtriage: float
    epss_total: float
    urgent_cvss: int
    urgent_epss: int
    urgent_kev: int
    urgent_ssvc: int
    urgent_total: int


def _order_baseline(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (f.enrichment.nvd_cvss_score or f.cvss_score or 0.0),
        reverse=True,
    )


def _order_ssvc(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=ssvc_order_key)


def _order_kev(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            f.enrichment.in_cisa_kev,
            f.enrichment.epss_score or 0.0,
            f.enrichment.nvd_cvss_score or f.cvss_score or 0.0,
        ),
        reverse=True,
    )


def _is_urgent(finding: Finding) -> bool:
    return (finding.triage or {}).get("priority") in ("P1", "P2")


def _order_epss(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            f.enrichment.epss_score or 0.0,
            f.enrichment.nvd_cvss_score or f.cvss_score or 0.0,
        ),
        reverse=True,
    )


def evaluate(findings: list[Finding],
             budgets: list[int] | None = None) -> list[EvalRow]:
    if not findings:
        return []
    base = _order_baseline(findings)
    epss_order = _order_epss(findings)
    kev_order = _order_kev(findings)
    ssvc_order = _order_ssvc(findings)
    kev_total = sum(1 for f in findings if f.enrichment.in_cisa_kev)
    epss_total = sum(f.enrichment.epss_score or 0.0 for f in findings)
    urgent_total = sum(1 for f in findings if _is_urgent(f))
    n = len(findings)
    budgets = budgets or sorted({max(1, n // 4), max(1, n // 2), n})

    rows = []
    for k in budgets:
        k = min(k, n)
        rows.append(EvalRow(
            k=k,
            kev_baseline=sum(1 for f in base[:k] if f.enrichment.in_cisa_kev),
            kev_epss=sum(1 for f in epss_order[:k] if f.enrichment.in_cisa_kev),
            kev_kev=sum(1 for f in kev_order[:k] if f.enrichment.in_cisa_kev),
            kev_ssvc=sum(1 for f in ssvc_order[:k] if f.enrichment.in_cisa_kev),
            kev_patchtriage=sum(
                1 for f in ssvc_order[:k] if f.enrichment.in_cisa_kev),
            kev_total=kev_total,
            epss_baseline=round(sum(f.enrichment.epss_score or 0 for f in base[:k]), 3),
            epss_epss=round(sum(f.enrichment.epss_score or 0 for f in epss_order[:k]), 3),
            epss_kev=round(sum(
                f.enrichment.epss_score or 0 for f in kev_order[:k]), 3),
            epss_ssvc=round(sum(
                f.enrichment.epss_score or 0 for f in ssvc_order[:k]), 3),
            epss_patchtriage=round(sum(
                f.enrichment.epss_score or 0 for f in ssvc_order[:k]), 3),
            epss_total=round(epss_total, 3),
            urgent_cvss=sum(1 for f in base[:k] if _is_urgent(f)),
            urgent_epss=sum(1 for f in epss_order[:k] if _is_urgent(f)),
            urgent_kev=sum(1 for f in kev_order[:k] if _is_urgent(f)),
            urgent_ssvc=sum(1 for f in ssvc_order[:k] if _is_urgent(f)),
            urgent_total=urgent_total,
        ))
    return rows
