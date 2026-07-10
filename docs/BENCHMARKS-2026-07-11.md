# PatchTriage benchmark results

Targets: widely used public container images (pinned tags). Budget k = 25 findings per image - what one team can realistically remediate in a week. Ground truth: CISA KEV membership and FIRST EPSS.

| Image | Findings | Budget k | KEV@k CVSS-order | KEV@k PatchTriage | EPSS@k CVSS-order | EPSS@k PatchTriage |
|---|---|---|---|---|---|---|
| centos:7 | 1534 | 25 | 0/2 | **2/2** | 4.227 | **20.021** |
| debian:10 | 68 | 25 | 0/0 | **0/0** | 1.932 | **4.543** |
| debian:9 | 71 | 25 | 0/0 | **0/0** | 0.832 | **0.885** |
| drupal:8.7 | 827 | 25 | 0/9 | **9/9** | 13.006 | **19.195** |
| golang:1.13 | 1893 | 25 | 0/11 | **11/11** | 6.231 | **15.027** |
| httpd:2.4.38 | 740 | 25 | 0/6 | **6/6** | 4.391 | **17.522** |
| mongo:3.6 | 133 | 25 | 0/0 | **0/0** | 0.771 | **1.81** |
| mysql:5.6 | 230 | 25 | 0/0 | **0/0** | 2.787 | **4.518** |
| nginx:1.14 | 217 | 25 | 1/1 | **1/1** | 3.042 | **5.624** |
| node:10 | 1131 | 25 | 0/3 | **3/3** | 4.922 | **14.89** |
| node:8 | 3335 | 25 | 0/8 | **8/8** | 3.736 | **17.145** |
| php:7.2 | 1489 | 25 | 0/10 | **10/10** | 5.451 | **15.57** |
| postgres:9.6 | 248 | 25 | 0/0 | **0/0** | 4.571 | **7.718** |
| python:2.7 | 4427 | 25 | 0/17 | **14/17** | 7.948 | **16.176** |
| python:3.5 | 3756 | 25 | 0/17 | **14/17** | 7.956 | **16.176** |
| ruby:2.5 | 3165 | 25 | 0/13 | **11/13** | 7.956 | **17.901** |
| tomcat:8.5.32 | 830 | 25 | 0/3 | **3/3** | 3.785 | **19.188** |
| wordpress:5.2 | 2664 | 25 | 0/18 | **7/18** | 13.996 | **22.674** |
| **Total** | | | **1/118** | **99/118** | **97.54** | **236.58** |

## What this means

* **118 findings in these images are on the CISA Known-Exploited-Vulnerabilities list** - attackers are using them in the wild right now. Those are the ones you cannot afford to leave outside the patch budget.
* Sorting by CVSS (the industry default) put **1 of 118** of them inside the weekly budget - it **missed 99%** of the actively exploited vulnerabilities.
* PatchTriage's ordering caught **99/118 (84%)** with the exact same budget.
* Measured by exploitation-probability mass (EPSS) captured inside the budget, PatchTriage carried **236.58** vs CVSS-order's **97.54** - **2.4x more**.

Ground truth is third-party (CISA KEV membership, FIRST EPSS), so the tool is not grading its own homework. Re-run `./benchmarks/run_benchmark.sh` to reproduce.