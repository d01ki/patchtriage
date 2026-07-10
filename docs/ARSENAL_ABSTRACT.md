# Black Hat Arsenal Submission Draft

> Benchmark numbers below are from `benchmarks/out/BENCHMARKS.md`
> (2026-07-11 run, pinned targets; reproduce with
> `./benchmarks/run_benchmark.sh`).

## Tool name

**PatchTriage**

## Tracks

Vulnerability Assessment / Defense / AI-ML Security

## Short description (one line)

Auditable AI triage for the vulnerability flood: deterministic exploitation
signals in, analyst-grade decisions out — every one machine-verified.

## Abstract

Frontier AI has industrialized vulnerability discovery. Scanners, fuzzers and
LLM-assisted auditing now produce findings far faster than any team can patch,
and the bottleneck has quietly moved from *finding* vulnerabilities to
*deciding what to fix first*. The industry's default answer — sort by CVSS —
is measurably wrong: in our benchmark across five widely used open-source
container images (18,000+ findings; nginx, redis, postgres, node, python),
CVSS-descending ordering placed **100% of the CISA known-exploited
vulnerabilities (0 of 8) outside a realistic weekly patch budget of 25
findings per image**, while PatchTriage's signal-based ordering caught all 8
with the same budget — and captured 7.6x more exploitation-probability mass
(FIRST EPSS) overall.

The obvious fix — "let an LLM prioritize" — introduces a new problem: how do
you trust an AI's risk decisions? PatchTriage's answer is an architecture we
call *auditable AI triage*. The LLM is never allowed to produce a number.
All quantitative signals are fetched deterministically from authoritative
sources (FIRST EPSS, CISA KEV, NVD) and cached locally; the model receives
those signals plus organizational context (asset criticality, internet
exposure) and returns only structured decisions with rationales. A separate
audit layer then machine-verifies every decision against the signals it was
given: fabricated numbers, downgraded known-exploited findings, patch actions
without an available fix, and silent divergence from a deterministic baseline
are all flagged for human review. You get frontier-model reasoning with
none of the hallucinated risk scores.

The same audit layer powers a cost architecture that makes frontier triage
affordable at estate scale: a *cascade* mode screens every finding with a
fast model and escalates only findings that are high-signal (CISA KEV, high
EPSS, exposed critical assets) or whose screening decision fails the machine
audit to the frontier model — with the routing decision itself recorded and
auditable. Bulk overnight re-triage runs at 50% API cost via batch
processing, and failed API calls degrade gracefully to the deterministic
baseline, tagged, so a network blip never aborts a 2,000-finding run.

PatchTriage ingests Trivy, Grype and osv-scanner output, deduplicates findings
across scanners via an alias graph, groups them into concrete remediation
actions ranked by risk actually removed, and emits a self-contained HTML
situation report. A built-in evaluation compares its ordering against
CVSS-sorting on every run, using third-party ground truth — the tool cannot
grade its own homework. Fully open source (Apache-2.0), Python, runs
air-gapped, demo in 60 seconds with no API keys.

## What's new / why Arsenal

* First open-source triage pipeline built around **machine-verified LLM
  decisions** — signals and reasoning are architecturally separated, and the
  audit trail is a first-class output.
* **Audit-driven model cascade**: the verification layer doubles as the
  escalation router, so frontier-model spend concentrates exactly where
  triage mistakes are expensive.
* Honest-by-construction evaluation (KEV@k / EPSS@k vs CVSS baseline)
  computed on every run and reproducible on public targets — the benchmark
  needs nothing but Docker (scanners fall back to pinned container images).
* Pluggable everything: scanners in, triage backends (deterministic rules,
  single-model Claude, or cascade), reports out. Runs in CI, offline, single
  pip install or `docker compose run demo`.

## Demo outline (approx. 15 min loop at the station)

1. `patchtriage demo` — 60-second air-gapped run on bundled scanner output.
2. The hook: CVSS 10.0 (xz backdoor) ranked *below* a CVSS 7.8 that is in
   active ransomware use — and the evaluation table proving the ordering wins.
3. Live run against a popular container image scanned that morning.
4. Flip `--triage cascade`: same signals, analyst-grade rationales — watch
   the audit layer route findings between the screening and frontier models,
   then catch a deliberately-injected fabricated score.
5. The HTML situation report: remediation ledger ranked by risk removed.

## Requirements

Laptop only. Runs offline; live-API portions degrade gracefully to cache.
