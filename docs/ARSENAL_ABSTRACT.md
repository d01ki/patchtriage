# Black Hat Europe 2026 Arsenal Submission

> Submission-ready draft for the Call for Tools closing 19 July 2026 at
> 23:59 Pacific Time. All claims below are limited to capabilities present in
> the public repository.

## Copy/paste fields

### Session Title

**PatchTriage: Turning Scanner Noise into Defensible SSVC Patch Decisions**

### Track

**Vulnerability Assessment**

### Secondary Track

**Risks**

### Format

**New Tool**

### Audience Level

**All**

### Theme

**All**

### Source Code

https://github.com/d01ki/patchtriage

### Tool URL

https://patchtriage.onrender.com

### Short Description

An open-source, local-first decision engine that turns scanner and SBOM
evidence into explainable CERT/CC SSVC patch deployment actions, with optional
AI explanations that cannot override the deterministic result.

### Tool Description / Abstract

Vulnerability scanners are very good at finding problems. They are much less
useful at answering the deployer's next question: **which remediation should
we execute first in this environment?** CVSS measures technical severity,
EPSS estimates future exploitation activity, and CISA KEV records observed
exploitation, but none alone accounts for how a particular system is exposed
or what its failure means to the organization.

PatchTriage is an open-source, local-first vulnerability decision engine that
implements the published CERT/CC SSVC Deployer model
(`ssvc:DT_DP:1.0.0`). It ingests Trivy, Grype, and osv-scanner JSON or resolves
CycloneDX/SPDX SBOMs via OSV; deduplicates findings; and adds EPSS,
KEV, NVD, and official vendor evidence. The engine applies Exploitation,
System Exposure, Automatable, and Human Impact to the official 72-path table.
Instead of another opaque score, it returns Defer, Scheduled, Out-of-Cycle,
or Immediate with the decision path, evidence provenance, confidence, and
confirmation requirements. Findings become package upgrades or mitigations,
not another flat CVE list.

Optional AI is deliberately placed outside the trust boundary. It may write a
clear rationale and remediation steps, but it cannot change the outcome,
action, or deadline. An audit recomputes every decision and detects
changed inputs, fabricated numbers, and tampered paths. Failed AI calls fall
back per finding to the deterministic result.

The Arsenal demo is hands-on and reproducible: attendees can import a real
scan or SBOM, change only the target environment and watch the same active CVE
move between official outcomes, compare CVSS-, EPSS-, KEV-first-, and
SSVC-ordered queues, and inspect the remediation plan. The one-click demo and
verifier need no network or API keys. Verification covers all 72 Deployer
paths, all 16 Human Impact combinations, target-input propagation,
repeatability, end-to-end behavior, and deliberate tampering, producing
SHA-256 evidence fingerprints.

### Notes for Reviewers

PatchTriage is Apache-2.0 open source and can be evaluated without creating an
account, using an API key, or trusting the hosted instance.

Fastest reproducible review:

```bash
git clone https://github.com/d01ki/patchtriage
cd patchtriage
docker compose run --rm demo
# Open ./out/demo_report.html
```

Independent conformance and repeatability evidence:

```bash
python -m pip install -e .
patchtriage verify --repeats 100 --output verification_report.json
```

The verification run is offline and checks:

- all 72 CERT/CC SSVC Deployer decision paths;
- all 16 official Mission Impact / Safety Impact to Human Impact mappings;
- three target-context scenarios for the same active CVE, proving that GUI
  context reaches the production decision engine;
- explicit conservative handling of unknown context;
- 300 repeated deterministic decisions when `--repeats 100` is used;
- two identical frozen end-to-end pipeline runs;
- detection of altered outcome, action, deadline, and decision path.

The repository CI tests Python 3.10, 3.11, and 3.12, runs the Docker demo, and
publishes demo and verification artifacts. The hosted URL exposes the same
GUI; it is a shared public demo, so use synthetic evidence only. The local
offline path is the recommended reviewer baseline.

Scope is intentionally narrow and verifiable. PatchTriage does not scan or
apply patches. Reachability and runtime observations are currently imported as
supporting evidence rather than collected automatically. Historical benchmark
files are retained for engineering history and are not presented as evidence
of the current SSVC engine's real-world effectiveness.

Documentation:

- README and quick start: https://github.com/d01ki/patchtriage#readme
- Reviewer protocol: https://github.com/d01ki/patchtriage/blob/main/docs/VALIDATION.md
- Full system design and technical specification:
  https://github.com/d01ki/patchtriage/blob/main/docs/PATCHTRIAGE_SYSTEM_DESIGN_JA.md

---

## Why this belongs in Arsenal

PatchTriage is designed for a station demo rather than a slide presentation.
An attendee can bring a scanner export or SBOM, describe one deployed system,
and immediately explore how threat evidence and local consequence change the
deployment action. Every click has a visible technical result: parsed and
deduplicated findings, a four-node SSVC path, confirmation warnings, a
package-level action, an audit result, and an offline HTML report.

The tool addresses a practical gap between vulnerability discovery and patch
execution. Its differentiator is not “AI ranks CVEs.” It is a standards-first
decision architecture in which:

1. authoritative threat and vendor evidence remains separate from generated
   explanation;
2. organizational context changes the decision through the official SSVC
   model;
3. AI is optional and technically unable to own priority;
4. every result can be reproduced and tamper-checked offline.

This combination makes the demo useful to operators, transparent to
researchers, and directly inspectable by reviewers.

## Technical differentiators

### 1. SSVC is the decision engine, not a label added after scoring

The exact CERT/CC table is encoded as categorical paths. CISA KEV establishes
active exploitation evidence but does not short-circuit stakeholder context.
EPSS remains a predictive 30-day signal and never becomes observed
exploitation. No weighted “risk score” competes with the SSVC outcome.

### 2. Context propagation is falsifiable

The offline verifier keeps CVE, package, exploitation evidence, Automatable,
and code constant while changing only System Exposure, Mission Impact, and
Safety Impact. The same active CVE must produce Immediate, Out-of-Cycle, and
Scheduled in three published paths. Entered and consumed context values are
both written to the evidence report.

### 3. AI has an enforceable boundary

The deterministic outcome is computed before the model is called and merged
back after the model responds. The audit recomputes the result independently.
A cascade backend uses urgency, confirmation requirements, and audit failure
as explicit escalation reasons and records those routing decisions.

### 4. The unit of work is a remediation

Findings are grouped by asset and package into concrete upgrade or mitigation
actions. A single package change can close multiple CVEs, which is closer to
how patch teams plan work than a flat vulnerability list.

### 5. Evaluation does not hide the baseline

Every run compares CVSS, EPSS, KEV-first, and SSVC orderings under the same
review budget. KEV coverage is identified as external observed-exploitation
evidence; SSVC urgent coverage is explicitly identified as a
context-consistency metric, not independent ground truth.

## Proposed station demo loop

The loop is designed to work in roughly 10–12 minutes and restart cleanly for
new attendees.

1. **The queue problem — 1 minute**
   Open the GUI and attach a Trivy/Grype file or launch the bundled Demo.

2. **Severity is not a deployment decision — 2 minutes**
   Show a CVSS 10.0 finding behind a lower-CVSS CISA KEV finding, then open the
   evidence rather than asking the audience to trust the ordering.

3. **The same CVE, a different system — 3 minutes**
   Change System Exposure, Mission Impact, and Safety Impact. Show the exact
   four-node SSVC path and the outcome change.

4. **From findings to work — 2 minutes**
   Open the package-level remediation plan, fixed-version evidence, official
   vendor advisories, and the self-contained HTML report.

5. **Trust but verify — 2 minutes**
   Run or display `patchtriage verify`, inject a changed decision path or
   fabricated number, and show the audit flag it.

6. **Optional audience input — ongoing**
   Import an attendee-provided scanner JSON or SBOM and discuss which context
   answers need confirmation.

## Demo requirements and contingency

- Primary requirement: presenter laptop and browser.
- No conference network is required for the bundled demo or verifier.
- No API key is required for deterministic SSVC, the bundled demo, reports,
  or verification.
- An internet connection is useful only for fresh EPSS/KEV/NVD/vendor data,
  OSV SBOM resolution, the hosted GUI, and optional AI explanations.
- If internet access is unavailable, the complete core story remains
  demonstrable from frozen evidence.

## Claim boundaries

The submission deliberately avoids three unsupported claims:

- It does not claim to analyze patch source-code diffs; vendor and fixed
  version records are used instead.
- It does not claim that the bundled three-finding demo proves real-world
  remediation effectiveness.
- It does not call reachability/runtime collection automatic; those fields are
  currently imported supporting evidence.

The defensible current claim is:

> PatchTriage conforms to the bundled official SSVC expectations, preserves
> GUI target context through the production pipeline, produces deterministic
> decisions for frozen evidence, detects altered decisions, and makes every
> inference visible for human confirmation.

## Alternate titles

If a shorter title is preferred:

1. **PatchTriage: Defensible Patch Decisions with SSVC**
2. **PatchTriage: From Vulnerability Noise to SSVC Action**
3. **PatchTriage: Stop Ranking CVEs. Start Deciding Patches.**
