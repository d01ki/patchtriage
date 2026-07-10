# PatchTriage benchmark results

Targets: widely used public container images (pinned tags). Budget k = 25 findings per image - what one team can realistically remediate in a week. Ground truth: CISA KEV membership and FIRST EPSS.

| Image | Findings | Budget k | KEV@k CVSS-order | KEV@k PatchTriage | EPSS@k CVSS-order | EPSS@k PatchTriage |
|---|---|---|---|---|---|---|
| nginx:1.24 | 621 | 25 | 0/0 | **0/0** | 1.499 | **13.062** |
| node:18.16-bullseye | 9783 | 25 | 0/4 | **4/4** | 2.72 | **22.538** |
| postgres:15.2 | 770 | 25 | 0/4 | **4/4** | 3.236 | **20.263** |
| python:3.10-bullseye | 6858 | 25 | 0/0 | **0/0** | 0.162 | **10.574** |
| redis:7.0 | 406 | 25 | 0/0 | **0/0** | 1.714 | **4.352** |
| **Total** | | | **0/8** | **8/8** | **9.33** | **70.79** |

## What this means

* **8 findings in these images are on the CISA Known-Exploited-Vulnerabilities list** - attackers are using them in the wild right now. Those are the ones you cannot afford to leave outside the patch budget.
* Sorting by CVSS (the industry default) put **0 of 8** of them inside the weekly budget - it **missed 100%** of the actively exploited vulnerabilities.
* PatchTriage's ordering caught **8/8 (100%)** with the exact same budget.
* Measured by exploitation-probability mass (EPSS) captured inside the budget, PatchTriage carried **70.79** vs CVSS-order's **9.33** - **7.6x more**.

Ground truth is third-party (CISA KEV membership, FIRST EPSS), so the tool is not grading its own homework. Re-run `./benchmarks/run_benchmark.sh` to reproduce.