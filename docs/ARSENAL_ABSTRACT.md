# Black Hat Arsenal Submission Draft

> The 2026-07-11 benchmark used the former signal-weighted ordering. It is
> retained as historical evidence, not as a performance claim for the current
> SSVC implementation. Re-run `./benchmarks/run_benchmark.sh` before using
> current numbers in a submission.

## Tool name

**PatchTriage**

## Tracks

Vulnerability Assessment / Defense / AI-ML Security

## Short description (one line)

Environment-specific vulnerability decisions: official SSVC Deployer outcomes,
authoritative threat evidence, and optional AI explanations — all auditable.

## Abstract

Frontier AI has industrialized vulnerability discovery. Scanners, fuzzers and
LLM-assisted auditing now produce findings far faster than any team can patch,
and the bottleneck has quietly moved from *finding* vulnerabilities to
*deciding what to fix first in this environment*. CVSS describes technical
severity, KEV records observed exploitation, and EPSS estimates future
exploitation probability; none alone answers whether this deployed instance
should be handled now, out-of-cycle, in normal maintenance, or deferred.
PatchTriage implements the official CERT/CC SSVC Deployer decision table and
combines Exploitation, System Exposure, Automatable, and Human Impact into
those four action-timing outcomes.

The obvious fix — "let an LLM prioritize" — introduces a new problem: how do
you trust an AI's risk decisions? PatchTriage does not ask you to. The LLM is
never allowed to produce a score or override priority. Authoritative evidence
(FIRST EPSS, CISA KEV, NVD and vendor advisories) and declared environment
context feed a deterministic SSVC path. Optional AI adds only explanations,
remediation steps, and uncertainty notes. A separate audit layer recomputes
SSVC and flags any changed priority, action, deadline, decision input,
fabricated number, or patch-without-fix recommendation.

The same audit layer powers a cost architecture that makes frontier triage
affordable at estate scale: a *cascade* mode screens every finding with a
fast model and escalates only urgent SSVC outcomes, context that needs human
confirmation, or explanations that fail the machine audit to the frontier
model — with the routing decision itself recorded and
auditable. Bulk overnight re-triage runs at 50% API cost via batch
processing, and failed API calls degrade gracefully to the deterministic
baseline, tagged, so a network blip never aborts a 2,000-finding run.

PatchTriage ingests Trivy, Grype and osv-scanner output, deduplicates findings
across scanners via an alias graph, groups them into concrete remediation
actions ordered by SSVC action timing, and emits a self-contained HTML
situation report. A built-in evaluation compares CVSS, EPSS, KEV-first, and
SSVC orderings on every run and distinguishes independent KEV coverage from
SSVC context-consistency. Fully open source (Apache-2.0), Python, runs
air-gapped, demo in 60 seconds with no API keys.

## What's new / why Arsenal

* Standards-first decision support built around the **CERT/CC SSVC Deployer
  model** — the full decision path, input confidence, and provenance are
  first-class output.
* **Audit-driven model cascade**: the verification layer doubles as the
  escalation router, so frontier-model spend concentrates exactly where
  triage mistakes are expensive.
* Four-way evaluation (CVSS / EPSS / KEV-first / SSVC) computed on every run,
  with external evidence and context-consistency labeled separately.
* Pluggable everything: scanners in, triage backends (deterministic SSVC,
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
5. The HTML situation report: official SSVC path, confirmation checklist, and
   remediation ledger ordered by action timing.

## Requirements

Laptop only. Runs offline; live-API portions degrade gracefully to cache.
