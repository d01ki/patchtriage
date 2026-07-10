#!/usr/bin/env python3
"""Aggregate benchmark reports into benchmarks/out/BENCHMARKS.md.

Reads every *__report.json produced by run_benchmark.sh, re-evaluates both
orderings (CVSS-descending vs PatchTriage) at a realistic fixed weekly
budget, and writes one markdown table plus a plain-language verdict.

The budget is k = 25 findings per image ("what one team realistically
remediates in a week"), not a percentage: on an image with 9,000+ findings a
25% budget would be thousands of findings and any ordering looks fine.
Tight budgets are where prioritization actually matters.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from patchtriage.evalcmp import evaluate
from patchtriage.models import Finding

BUDGET = 25  # findings per image per week


def main(out_dir: str) -> None:
    out = Path(out_dir)
    rows = []
    for report in sorted(out.glob("*__report.json")):
        image = report.name.replace("__report.json", "").replace("_", ":", 1)
        data = json.loads(report.read_text(encoding="utf-8"))
        findings = [Finding.model_validate(f) for f in data.get("findings", [])]
        if not findings:
            continue
        r = evaluate(findings, budgets=[BUDGET])[0]
        rows.append((image, len(findings), r))

    if not rows:
        print("no reports found", file=sys.stderr)
        sys.exit(1)

    lines = [
        "# PatchTriage benchmark results",
        "",
        "Targets: widely used public container images (pinned tags). "
        f"Budget k = {BUDGET} findings per image - what one team can "
        "realistically remediate in a week. Ground truth: CISA KEV "
        "membership and FIRST EPSS.",
        "",
        "| Image | Findings | Budget k | KEV@k CVSS-order | KEV@k PatchTriage "
        "| EPSS@k CVSS-order | EPSS@k PatchTriage |",
        "|---|---|---|---|---|---|---|",
    ]
    tot_kb = tot_kp = tot_kt = 0
    tot_eb = tot_ep = 0.0
    for image, n, r in rows:
        lines.append(
            f"| {image} | {n} | {r.k} "
            f"| {r.kev_baseline}/{r.kev_total} "
            f"| **{r.kev_patchtriage}/{r.kev_total}** "
            f"| {r.epss_baseline} | **{r.epss_patchtriage}** |")
        tot_kb += r.kev_baseline
        tot_kp += r.kev_patchtriage
        tot_kt += r.kev_total
        tot_eb += r.epss_baseline
        tot_ep += r.epss_patchtriage
    lines += [
        f"| **Total** | | | **{tot_kb}/{tot_kt}** | **{tot_kp}/{tot_kt}** "
        f"| **{tot_eb:.2f}** | **{tot_ep:.2f}** |",
    ]

    # Plain-language verdict - this is the part that goes into the abstract.
    missed_pct = round(100 * (1 - tot_kb / tot_kt)) if tot_kt else 0
    caught_pct = round(100 * tot_kp / tot_kt) if tot_kt else 0
    epss_ratio = (tot_ep / tot_eb) if tot_eb else 0.0
    verdict = [
        "",
        "## What this means",
        "",
        f"* **{tot_kt} findings in these images are on the CISA "
        f"Known-Exploited-Vulnerabilities list** - attackers are using them "
        f"in the wild right now. Those are the ones you cannot afford to "
        f"leave outside the patch budget.",
        f"* Sorting by CVSS (the industry default) put **{tot_kb} of "
        f"{tot_kt}** of them inside the weekly budget - it **missed "
        f"{missed_pct}%** of the actively exploited vulnerabilities.",
        f"* PatchTriage's ordering caught **{tot_kp}/{tot_kt} "
        f"({caught_pct}%)** with the exact same budget.",
        f"* Measured by exploitation-probability mass (EPSS) captured inside "
        f"the budget, PatchTriage carried **{tot_ep:.2f}** vs CVSS-order's "
        f"**{tot_eb:.2f}**"
        + (f" - **{epss_ratio:.1f}x more**." if epss_ratio else "."),
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
