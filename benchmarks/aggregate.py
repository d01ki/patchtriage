#!/usr/bin/env python3
"""Aggregate benchmark reports into benchmarks/out/BENCHMARKS.md.

Reads every *__report.json produced by run_benchmark.sh and re-evaluates four
orderings (CVSS, EPSS, KEV-first, and SSVC) at a fixed review budget.

The budget is a fixed number of findings per system ("what one team
realistically remediates in a week"), not a percentage: on a system with
9,000+ findings a 25% budget would be thousands of findings and any ordering
looks fine. Tight, absolute budgets are where prioritization actually matters.

KEV coverage is independent observed-exploitation evidence. SSVC-urgent
coverage measures whether the ordering preserves the environment-specific
Immediate and Out-of-Cycle queue; it is not presented as external truth.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from patchtriage.evalcmp import evaluate
from patchtriage.models import Finding

BUDGET = 50           # findings per system per week (primary)
BUDGET_TIGHT = 25     # a stricter budget, shown for comparison


def _load_systems(out: Path):
    systems = []
    for report in sorted(out.glob("*__report.json")):
        data = json.loads(report.read_text(encoding="utf-8"))
        findings = [Finding.model_validate(f) for f in data.get("findings", [])]
        if not findings:
            continue
        image = findings[0].asset.identifier
        if not image or image in ("override", "interactive"):
            image = report.name.replace("__report.json", "").replace("_", ":", 1)
        systems.append((image, findings))
    return systems


def _totals(systems, budget):
    totals = {
        "kev_cvss": 0, "kev_epss": 0, "kev_kev": 0, "kev_ssvc": 0,
        "kev_total": 0,
        "mass_cvss": 0.0, "mass_epss": 0.0, "mass_kev": 0.0,
        "mass_ssvc": 0.0,
        "urgent_cvss": 0, "urgent_epss": 0, "urgent_kev": 0,
        "urgent_ssvc": 0, "urgent_total": 0,
    }
    per = []
    for image, findings in systems:
        r = evaluate(findings, budgets=[budget])[0]
        per.append((image, len(findings), r))
        totals["kev_cvss"] += r.kev_baseline
        totals["kev_epss"] += r.kev_epss
        totals["kev_kev"] += r.kev_kev
        totals["kev_ssvc"] += r.kev_ssvc
        totals["kev_total"] += r.kev_total
        totals["mass_cvss"] += r.epss_baseline
        totals["mass_epss"] += r.epss_epss
        totals["mass_kev"] += r.epss_kev
        totals["mass_ssvc"] += r.epss_ssvc
        totals["urgent_cvss"] += r.urgent_cvss
        totals["urgent_epss"] += r.urgent_epss
        totals["urgent_kev"] += r.urgent_kev
        totals["urgent_ssvc"] += r.urgent_ssvc
        totals["urgent_total"] += r.urgent_total
    return per, totals


def main(out_dir: str) -> None:
    out = Path(out_dir)
    systems = _load_systems(out)
    if not systems:
        print("no reports found", file=sys.stderr)
        sys.exit(1)

    per, totals = _totals(systems, BUDGET)
    _, tight = _totals(systems, BUDGET_TIGHT)

    total_findings = sum(n for _, n, _ in per)
    total_reviewed = sum(r.k for _, _, r in per)
    review_reduction = (
        100 * (1 - total_reviewed / total_findings) if total_findings else 0.0
    )
    kev_coverage = (
        100 * totals["kev_ssvc"] / totals["kev_total"]
        if totals["kev_total"] else 0.0
    )
    urgent_coverage = (
        100 * totals["urgent_ssvc"] / totals["urgent_total"]
        if totals["urgent_total"] else 0.0
    )

    lines = [
        "# PatchTriage benchmark results",
        "",
        f"Targets: pinned public container images. Budget k = {BUDGET} "
        "findings per system - what one team can realistically remediate in a "
        "week (one package upgrade usually closes many findings). All targets "
        "use the documented benchmark SSVC context profile: Open exposure, "
        "Automatable Yes, MEF Support Crippled mission impact, and Negligible "
        "safety impact.",
        "",
        "## User outcomes",
        "",
        "| Outcome | Result |",
        "|---|---:|",
        f"| First-pass review queue | **{total_findings:,} -> "
        f"{total_reviewed:,} findings ({review_reduction:.1f}% smaller)** |",
        f"| Known-exploited coverage in SSVC queue | **{totals['kev_ssvc']}/{totals['kev_total']} ({kev_coverage:.1f}%)** |",
        f"| Environment-urgent coverage in SSVC queue | **{totals['urgent_ssvc']}/{totals['urgent_total']} ({urgent_coverage:.1f}%)** |",
        "",
        "| Image | Findings | k | KEV CVSS | KEV EPSS | KEV-first | KEV SSVC | Urgent CVSS | Urgent EPSS | Urgent KEV | Urgent SSVC |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for image, n, r in per:
        lines.append(
            f"| {image} | {n} | {r.k} | {r.kev_baseline}/{r.kev_total} "
            f"| {r.kev_epss}/{r.kev_total} | {r.kev_kev}/{r.kev_total} "
            f"| **{r.kev_ssvc}/{r.kev_total}** "
            f"| {r.urgent_cvss}/{r.urgent_total} | {r.urgent_epss}/{r.urgent_total} "
            f"| {r.urgent_kev}/{r.urgent_total} "
            f"| **{r.urgent_ssvc}/{r.urgent_total}** |")
    lines += [
        f"| **Total** | **{total_findings:,}** | **{total_reviewed:,}** "
        f"| **{totals['kev_cvss']}/{totals['kev_total']}** "
        f"| **{totals['kev_epss']}/{totals['kev_total']}** "
        f"| **{totals['kev_kev']}/{totals['kev_total']}** "
        f"| **{totals['kev_ssvc']}/{totals['kev_total']}** "
        f"| **{totals['urgent_cvss']}/{totals['urgent_total']}** "
        f"| **{totals['urgent_epss']}/{totals['urgent_total']}** "
        f"| **{totals['urgent_kev']}/{totals['urgent_total']}** "
        f"| **{totals['urgent_ssvc']}/{totals['urgent_total']}** |",
    ]

    verdict = [
        "",
        "## What this means",
        "",
        f"* The first-pass queue fell from **{total_findings:,} raw findings "
        f"to {total_reviewed:,} prioritized reviews ({review_reduction:.1f}% "
        f"smaller)** while preserving {totals['urgent_ssvc']} of "
        f"{totals['urgent_total']} environment-urgent SSVC decisions.",
        f"* The SSVC queue surfaced **{totals['kev_ssvc']}/"
        f"{totals['kev_total']} CISA KEV findings**; compare that with CVSS "
        f"({totals['kev_cvss']}), EPSS ({totals['kev_epss']}), and an explicit "
        f"KEV-first baseline ({totals['kev_kev']}).",
        f"* At the tighter {BUDGET_TIGHT}/system budget, SSVC surfaced "
        f"{tight['kev_ssvc']}/{tight['kev_total']} KEV findings and "
        f"{tight['urgent_ssvc']}/{tight['urgent_total']} environment-urgent "
        "decisions.",
        "",
        "CISA KEV membership is third-party evidence. Environment-urgent "
        "coverage is a self-consistency measure for the stated SSVC profile, "
        "not independent ground truth. Re-run "
        "`./benchmarks/run_benchmark.sh` to reproduce.",
    ]
    lines += verdict
    (out / "BENCHMARKS.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "out")
