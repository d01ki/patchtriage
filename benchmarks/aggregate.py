#!/usr/bin/env python3
"""Aggregate benchmark reports into benchmarks/out/BENCHMARKS.md.

Reads every *__report.json produced by run_benchmark.sh and builds one
markdown table: per image, at budget k = 25% of findings, how many CISA-KEV
(known exploited) findings each ordering catches, and how much EPSS
(exploitation probability mass) each captures.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main(out_dir: str) -> None:
    out = Path(out_dir)
    rows = []
    for report in sorted(out.glob("*__report.json")):
        image = report.name.replace("__report.json", "").replace("_", ":", 1)
        data = json.loads(report.read_text(encoding="utf-8"))
        evals = data.get("evaluation", [])
        if not evals:
            continue
        r = evals[0]  # smallest budget (n/4) — the "realistic week" scenario
        n = len(data.get("findings", []))
        rows.append((image, n, r))

    if not rows:
        print("no reports found", file=sys.stderr)
        sys.exit(1)

    lines = [
        "# PatchTriage benchmark results",
        "",
        "Targets: widely used public container images (pinned tags). "
        "Budget k = 25% of deduplicated findings — 'what you can realistically "
        "patch this week'. Ground truth: CISA KEV membership and FIRST EPSS.",
        "",
        "| Image | Findings | Budget k | KEV@k CVSS-order | KEV@k PatchTriage "
        "| EPSS@k CVSS-order | EPSS@k PatchTriage |",
        "|---|---|---|---|---|---|---|",
    ]
    tot_kb = tot_kp = tot_kt = 0
    for image, n, r in rows:
        lines.append(
            f"| {image} | {n} | {r['k']} "
            f"| {r['kev_baseline']}/{r['kev_total']} "
            f"| **{r['kev_patchtriage']}/{r['kev_total']}** "
            f"| {r['epss_baseline']} | **{r['epss_patchtriage']}** |")
        tot_kb += r["kev_baseline"]
        tot_kp += r["kev_patchtriage"]
        tot_kt += r["kev_total"]
    lines += [
        f"| **Total** | | | **{tot_kb}/{tot_kt}** | **{tot_kp}/{tot_kt}** | | |",
        "",
        f"CVSS-descending ordering caught {tot_kb}/{tot_kt} known-exploited "
        f"findings inside the budget; PatchTriage caught {tot_kp}/{tot_kt}.",
    ]
    (out / "BENCHMARKS.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "out")
