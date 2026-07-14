"""Practicality evaluation.

Claim to prove: ordering work by PatchTriage priority front-loads *actually
exploited* vulnerabilities better than the industry-default CVSS-descending
order.

Method: for the same finding set, produce three orderings —
    CVSS baseline: CVSS descending
    EPSS baseline: EPSS descending (the strongest simple alternative)
    patchtriage  : triage priority, then deterministic risk score
and compare, at each budget k ("you only have time to fix k findings"):

    KEV@k    — how many known-exploited (CISA KEV) findings are inside top-k
    EPSS@k   — sum of exploitation probability captured inside top-k

Both metrics are grounded in third-party data (CISA / FIRST), not in our own
scoring, so the comparison cannot be gamed by the tool itself.
"""

from __future__ import annotations

from pydantic import BaseModel

from .models import Finding
from .plan import _PRIORITY_RANK, finding_risk


class EvalRow(BaseModel):
    k: int
    kev_baseline: int
    kev_epss: int
    kev_patchtriage: int
    kev_total: int
    epss_baseline: float
    epss_epss: float
    epss_patchtriage: float
    epss_total: float


def _order_baseline(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (f.enrichment.nvd_cvss_score or f.cvss_score or 0.0),
        reverse=True,
    )


def _order_patchtriage(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            _PRIORITY_RANK.get((f.triage or {}).get("priority", "P4"), 9),
            -finding_risk(f),
        ),
    )


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
    base = _order_baseline(findings)
    epss_order = _order_epss(findings)
    ours = _order_patchtriage(findings)
    kev_total = sum(1 for f in findings if f.enrichment.in_cisa_kev)
    epss_total = sum(f.enrichment.epss_score or 0.0 for f in findings)
    n = len(findings)
    budgets = budgets or sorted({max(1, n // 4), max(1, n // 2), n})

    rows = []
    for k in budgets:
        k = min(k, n)
        rows.append(EvalRow(
            k=k,
            kev_baseline=sum(1 for f in base[:k] if f.enrichment.in_cisa_kev),
            kev_epss=sum(1 for f in epss_order[:k] if f.enrichment.in_cisa_kev),
            kev_patchtriage=sum(1 for f in ours[:k] if f.enrichment.in_cisa_kev),
            kev_total=kev_total,
            epss_baseline=round(sum(f.enrichment.epss_score or 0 for f in base[:k]), 3),
            epss_epss=round(sum(f.enrichment.epss_score or 0 for f in epss_order[:k]), 3),
            epss_patchtriage=round(sum(f.enrichment.epss_score or 0 for f in ours[:k]), 3),
            epss_total=round(epss_total, 3),
        ))
    return rows
