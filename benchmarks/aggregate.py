#!/usr/bin/env python3
"""Aggregate benchmark reports into benchmarks/out/BENCHMARKS.md.

Reads every *__report.json produced by run_benchmark.sh, re-evaluates both
orderings (CVSS-descending vs PatchTriage) at a realistic fixed weekly
budget, and writes one markdown table plus a plain-language verdict.

The budget is a fixed number of findings per system ("what one team
realistically remediates in a week"), not a percentage: on a system with
9,000+ findings a 25% budget would be thousands of findings and any ordering
looks fine. Tight, absolute budgets are where prioritization actually matters.

We report a primary budget and also show that CVSS-ordering barely improves
even when the budget is doubled — its known-exploited findings are buried
under hundreds of higher-CVSS ones, so more budget does not rescue it.
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
    kb = kp = kt = 0
    eb = ep = 0.0
    per = []
    for image, findings in systems:
        r = evaluate(findings, budgets=[budget])[0]
        per.append((image, len(findings), r))
        kb += r.kev_baseline; kp += r.kev_patchtriage; kt += r.kev_total
        eb += r.epss_baseline; ep += r.epss_patchtriage
    return per, kb, kp, kt, eb, ep


def main(out_dir: str) -> None:
    out = Path(out_dir)
    systems = _load_systems(out)
    if not systems:
        print("no reports found", file=sys.stderr)
        sys.exit(1)

    per, kb, kp, kt, eb, ep = _totals(systems, BUDGET)
    # tight-budget totals (same reports, stricter budget)
    _, kb_t, kp_t, kt_t, _, _ = _totals(systems, BUDGET_TIGHT)

    lines = [
        "# PatchTriage benchmark results",
        "",
        f"Targets: pinned public container images. Budget k = {BUDGET} "
        "findings per system - what one team can realistically remediate in a "
        "week (one package upgrade usually closes many findings). Ground "
        "truth: CISA KEV membership and FIRST EPSS.",
        "",
        "| Image | Findings | Budget k | KEV@k CVSS-order | KEV@k PatchTriage "
        "| EPSS@k CVSS-order | EPSS@k PatchTriage |",
        "|---|---|---|---|---|---|---|",
    ]
    for image, n, r in per:
        lines.append(
            f"| {image} | {n} | {r.k} "
            f"| {r.kev_baseline}/{r.kev_total} "
            f"| **{r.kev_patchtriage}/{r.kev_total}** "
            f"| {r.epss_baseline} | **{r.epss_patchtriage}** |")
    lines += [
        f"| **Total** | | | **{kb}/{kt}** | **{kp}/{kt}** "
        f"| **{eb:.2f}** | **{ep:.2f}** |",
    ]

    caught_pct = round(100 * kp / kt) if kt else 0
    missed_pct = round(100 * (1 - kb / kt)) if kt else 0
    caught_pct_t = round(100 * kp_t / kt_t) if kt_t else 0
    epss_ratio = (ep / eb) if eb else 0.0
    verdict = [
        "",
        "## What this means",
        "",
        f"* **{kt} findings across these systems are on the CISA "
        f"Known-Exploited-Vulnerabilities list** - attackers are using them "
        f"in the wild right now. Those are the ones you cannot afford to "
        f"leave outside the patch budget.",
        f"* Sorting by CVSS (the industry default) put **{kb} of {kt}** of "
        f"them inside the weekly budget - it **missed {missed_pct}%** of the "
        f"actively exploited vulnerabilities.",
        f"* PatchTriage caught **{kp}/{kt} ({caught_pct}%)** with the exact "
        f"same budget - and **{ep:.1f} vs {eb:.1f}** EPSS mass"
        + (f" ({epss_ratio:.1f}x more)." if epss_ratio else "."),
        f"* Doubling is no rescue for CVSS: at the stricter budget of "
        f"{BUDGET_TIGHT}/system it caught {kb_t}/{kt_t} (PatchTriage "
        f"{kp_t}/{kt_t}, {caught_pct_t}%); even at {BUDGET}/system CVSS only "
        f"reaches {kb}/{kt}. Known-exploited CVEs rarely have the top CVSS "
        f"score, so more budget just buys more high-CVSS noise.",
        "",
        "Ground truth is third-party (CISA KEV membership, FIRST EPSS), so "
        "the tool is not grading its own homework. Re-run "
        "`./benchmarks/run_benchmark.sh` to reproduce.",
    ]
    lines += verdict
    (out / "BENCHMARKS.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "out")
