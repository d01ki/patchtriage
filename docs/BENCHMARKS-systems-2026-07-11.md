# PatchTriage benchmark results

Targets: widely used public container images (pinned tags). Budget k = 25 findings per image - what one team can realistically remediate in a week. Ground truth: CISA KEV membership and FIRST EPSS.

| Image | Findings | Budget k | KEV@k CVSS-order | KEV@k PatchTriage | EPSS@k CVSS-order | EPSS@k PatchTriage |
|---|---|---|---|---|---|---|
| ghost:3.42 | 511 | 25 | 0/0 | **0/0** | 1.34 | **11.757** |
| gitea:gitea_1.13.0 | 353 | 25 | 0/0 | **0/0** | 2.89 | **13.515** |
| grafana:grafana_8.0.0 | 234 | 25 | 0/0 | **0/0** | 3.615 | **9.993** |
| jenkins:jenkins_2.319-slim | 1267 | 25 | 0/10 | **10/10** | 7.819 | **20.071** |
| mattermost:mattermost-team-edition_5.30.0 | 317 | 25 | 0/0 | **0/0** | 3.361 | **12.936** |
| metabase:metabase_v0.40.0 | 349 | 25 | 1/2 | **2/2** | 5.213 | **18.301** |
| nextcloud:20-apache | 9700 | 25 | 0/28 | **13/28** | 12.414 | **21.584** |
| redmine:4.1 | 9432 | 25 | 0/22 | **18/22** | 8.478 | **14.393** |
| sonarqube:8.9-community | 120 | 25 | 0/0 | **0/0** | 3.559 | **6.796** |
| sonatype:nexus3_3.30.0 | 1936 | 25 | 0/9 | **9/9** | 8.071 | **19.499** |
| wordpress:5.5 | 2137 | 25 | 0/16 | **11/16** | 14.6 | **19.661** |
| **Total** | | | **1/87** | **63/87** | **71.36** | **168.51** |

## What this means

* **87 findings in these images are on the CISA Known-Exploited-Vulnerabilities list** - attackers are using them in the wild right now. Those are the ones you cannot afford to leave outside the patch budget.
* Sorting by CVSS (the industry default) put **1 of 87** of them inside the weekly budget - it **missed 99%** of the actively exploited vulnerabilities.
* PatchTriage's ordering caught **63/87 (72%)** with the exact same budget.
* Measured by exploitation-probability mass (EPSS) captured inside the budget, PatchTriage carried **168.51** vs CVSS-order's **71.36** - **2.4x more**.

Ground truth is third-party (CISA KEV membership, FIRST EPSS), so the tool is not grading its own homework. Re-run `./benchmarks/run_benchmark.sh` to reproduce.