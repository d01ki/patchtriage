"""Layer 6 — Remediation planning.

Individual findings are the wrong unit of work: nobody patches one CVE at a
time. One package upgrade typically closes many findings at once. This layer
groups findings into concrete *actions* ("upgrade libc6 on web-frontend to
2.36-9+deb12u3") and ranks actions by **risk reduced per action**, so the
patch plan starts with the moves that buy the most safety.

Risk model (deterministic, explainable):
    finding_risk = exploitation_likelihood x impact x asset_weight
      exploitation_likelihood = 1.0 if KEV else EPSS (floor 0.01)
      impact                  = CVSS/10 (fallback: severity ladder)
      asset_weight            = criticality x exposure multiplier
"""

from __future__ import annotations

from collections import defaultdict

from pydantic import BaseModel, Field

from .models import Finding, Severity

_SEV_IMPACT = {
    Severity.CRITICAL: 0.95, Severity.HIGH: 0.8, Severity.MEDIUM: 0.5,
    Severity.LOW: 0.25, Severity.NEGLIGIBLE: 0.1, Severity.UNKNOWN: 0.4,
}
_CRIT_WEIGHT = {"critical": 2.0, "high": 1.5, "medium": 1.0,
                "low": 0.6, "unknown": 1.0}
_PRIORITY_RANK = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}


def finding_risk(f: Finding) -> float:
    e = f.enrichment
    likelihood = 1.0 if e.in_cisa_kev else max(e.epss_score or 0.0, 0.01)
    score = e.nvd_cvss_score or f.cvss_score
    impact = (score / 10.0) if score else _SEV_IMPACT[f.severity]
    weight = _CRIT_WEIGHT.get(f.asset.criticality, 1.0)
    if f.asset.internet_exposed:
        weight *= 1.5
    return round(likelihood * impact * weight, 4)


class Action(BaseModel):
    """One concrete unit of remediation work."""

    action_id: str
    kind: str                      # upgrade | mitigate | investigate
    summary: str                   # human-readable instruction
    asset: str
    package: str
    target_version: str = ""
    finding_keys: list[str] = Field(default_factory=list)
    cves: list[str] = Field(default_factory=list)
    risk_reduced: float = 0.0      # sum of finding risks this action closes
    top_priority: str = "P4"       # best (lowest) triage priority among findings
    deadline_days: int = 90
    kev_count: int = 0
    rationales: list[str] = Field(default_factory=list)


def build_plan(findings: list[Finding]) -> list[Action]:
    """Group findings into actions and rank by risk reduced."""
    groups: dict[tuple, list[Finding]] = defaultdict(list)
    for f in findings:
        if f.package.fixed_version:
            key = ("upgrade", f.asset.identifier, f.package.name)
        else:
            key = ("mitigate", f.asset.identifier, f.package.name)
        groups[key].append(f)

    actions: list[Action] = []
    for (kind, asset, pkg), group in groups.items():
        # target = highest fixed_version mentioned (string max is a heuristic;
        # ecosystem-aware version comparison is a roadmap item)
        target = max((g.package.fixed_version for g in group), default="")
        prios = [(g.triage or {}).get("priority", "P4") for g in group]
        top = min(prios, key=lambda p: _PRIORITY_RANK.get(p, 9))
        deadlines = [(g.triage or {}).get("suggested_deadline_days", 90)
                     for g in group]
        if kind == "upgrade":
            summary = f"Upgrade {pkg} to {target} on {asset}"
        else:
            summary = (f"No fix available for {pkg} on {asset} - "
                       f"apply mitigations / monitor vendor")
        actions.append(Action(
            action_id=f"{kind}:{asset}:{pkg}",
            kind=kind,
            summary=summary,
            asset=asset,
            package=pkg,
            target_version=target,
            finding_keys=[g.key for g in group],
            cves=sorted({g.vuln_id for g in group}),
            risk_reduced=round(sum(finding_risk(g) for g in group), 4),
            top_priority=top,
            deadline_days=min(deadlines) if deadlines else 90,
            kev_count=sum(1 for g in group if g.enrichment.in_cisa_kev),
            rationales=[(g.triage or {}).get("rationale", "") for g in group][:3],
        ))

    actions.sort(key=lambda a: (_PRIORITY_RANK.get(a.top_priority, 9),
                                -a.risk_reduced))
    return actions
