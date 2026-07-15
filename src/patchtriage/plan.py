"""Layer 6 — Remediation planning.

Individual findings are the wrong unit of work: nobody patches one CVE at a
time. One package upgrade typically closes many findings at once. This layer
groups findings into concrete *actions* ("upgrade libc6 on web-frontend to
2.36-9+deb12u3") and ranks actions by the categorical SSVC Deployer outcome.
No proprietary arithmetic risk score competes with or modifies that outcome.
"""

from __future__ import annotations

from collections import defaultdict

from pydantic import BaseModel, Field

from .models import Finding
from .ssvc import ssvc_sort_key

_PRIORITY_RANK = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}


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
    top_priority: str = "P4"       # best (lowest) triage priority among findings
    deadline_days: int = 90
    kev_count: int = 0
    rationales: list[str] = Field(default_factory=list)


def build_plan(findings: list[Finding]) -> list[Action]:
    """Group findings into actions and rank by SSVC action timing."""
    groups: dict[tuple, list[Finding]] = defaultdict(list)
    for f in findings:
        if f.package.fixed_version:
            key = ("upgrade", f.asset.identifier, f.package.name)
        else:
            key = ("mitigate", f.asset.identifier, f.package.name)
        groups[key].append(f)

    actions: list[Action] = []
    ordering: dict[str, tuple] = {}
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
        action_id = f"{kind}:{asset}:{pkg}"
        top_group = [
            finding for finding in group
            if (finding.triage or {}).get("priority", "P4") == top
        ]
        ordering[action_id] = max(
            (ssvc_sort_key(finding) for finding in (top_group or group)),
            default=(0, 0, 0, 0, 0.0, 0.0),
        )
        actions.append(Action(
            action_id=action_id,
            kind=kind,
            summary=summary,
            asset=asset,
            package=pkg,
            target_version=target,
            finding_keys=[g.key for g in group],
            cves=sorted({g.vuln_id for g in group}),
            top_priority=top,
            deadline_days=min(deadlines) if deadlines else 90,
            kev_count=sum(1 for g in group if g.enrichment.in_cisa_kev),
            rationales=[(g.triage or {}).get("rationale", "") for g in group][:3],
        ))

    actions.sort(key=lambda action: (
        _PRIORITY_RANK.get(action.top_priority, 9),
        *(-value for value in ordering[action.action_id]),
    ))
    return actions
