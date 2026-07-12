# PatchTriage benchmark results

Targets: pinned public container images. Budget k = 50 findings per system - what one team can realistically remediate in a week (one package upgrade usually closes many findings). Ground truth: CISA KEV membership and FIRST EPSS.

| Image | Findings | Budget k | KEV@k CVSS-order | KEV@k PatchTriage | EPSS@k CVSS-order | EPSS@k PatchTriage |
|---|---|---|---|---|---|---|
| ghost:3.42 | 511 | 50 | 0/0 | **0/0** | 3.399 | **12.576** |
| gitea/gitea:1.13.0 | 353 | 50 | 0/0 | **0/0** | 5.225 | **14.499** |
| grafana/grafana:8.0.0 | 234 | 50 | 0/0 | **0/0** | 6.196 | **11.009** |
| jenkins/jenkins:2.319-slim | 1267 | 50 | 0/10 | **10/10** | 12.161 | **37.084** |
| mattermost/mattermost-team-edition:5.30.0 | 317 | 50 | 0/0 | **0/0** | 6.113 | **14.041** |
| metabase/metabase:v0.40.0 | 349 | 50 | 1/2 | **2/2** | 9.139 | **24.503** |
| nextcloud:20-apache | 9700 | 50 | 0/28 | **26/28** | 16.959 | **35.759** |
| redmine:4.1 | 9432 | 50 | 0/22 | **21/22** | 8.663 | **34.132** |
| sonarqube:8.9-community | 120 | 50 | 0/0 | **0/0** | 4.75 | **7.291** |
| sonatype/nexus3:3.30.0 | 1936 | 50 | 0/9 | **9/9** | 10.591 | **35.38** |
| wordpress:5.5 | 2137 | 50 | 0/16 | **16/16** | 19.406 | **38.529** |
| **Total** | | | **1/87** | **84/87** | **102.60** | **264.80** |

## What this means

* **87 findings across these systems are on the CISA Known-Exploited-Vulnerabilities list** - attackers are using them in the wild right now. Those are the ones you cannot afford to leave outside the patch budget.
* Sorting by CVSS (the industry default) put **1 of 87** of them inside the weekly budget - it **missed 99%** of the actively exploited vulnerabilities.
* PatchTriage caught **84/87 (97%)** with the exact same budget - and **264.8 vs 102.6** EPSS mass (2.6x more).
* Doubling is no rescue for CVSS: at the stricter budget of 25/system it caught 1/87 (PatchTriage 63/87, 72%); even at 50/system CVSS only reaches 1/87. Known-exploited CVEs rarely have the top CVSS score, so more budget just buys more high-CVSS noise.

Ground truth is third-party (CISA KEV membership, FIRST EPSS), so the tool is not grading its own homework. Re-run `./benchmarks/run_benchmark.sh` to reproduce.