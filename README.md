# PatchTriage

[![Deploy](https://github.com/d01ki/PatchTriage/actions/workflows/deploy.yml/badge.svg)](https://github.com/d01ki/PatchTriage/actions/workflows/deploy.yml)
[![CI](https://github.com/d01ki/PatchTriage/actions/workflows/ci.yml/badge.svg)](https://github.com/d01ki/PatchTriage/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![Decision model: CERT/CC SSVC Deployer](https://img.shields.io/badge/decision-CERT%2FCC%20SSVC%20Deployer-5b5bd6.svg)](https://certcc.github.io/SSVC/howto/deployer_tree/)

PatchTriage turns scanner evidence into environment-specific patch deployment
decisions. It ingests vulnerability scans or SBOMs, deduplicates findings,
adds exploitation and vendor evidence, and applies the deterministic
[CERT/CC SSVC Deployer model](https://certcc.github.io/SSVC/howto/deployer_tree/).

The output is a defensible action queue with one of four plain-language SSVC
outcomes: **Immediate**, **Out-of-Cycle**, **Scheduled**, or **Defer**.

**Live tool:** [https://patch-triage.com/](https://patch-triage.com/)

> AI never chooses the SSVC outcome and never invents a score. Optional AI
> backends can improve explanations and remediation guidance only. Every
> result is checked again by the deterministic engine.

## Why PatchTriage uses SSVC

PatchTriage is an **SSVC-first patch deployment decision tool**. It implements
the published CERT/CC Deployer decision model (`ssvc:DT_DP:1.0.0`) rather than
inventing a proprietary risk score. For every finding, the engine records the
four decision points that determine deployment timing:

```text
Exploitation + System Exposure + Automatable + Human Impact
                              |
                              v
           Defer / Scheduled / Out-of-Cycle / Immediate
```

Mission Impact and Safety Impact are combined through the published Human
Impact table. CISA KEV can establish `Exploitation = Active`, but it does not
bypass the SSVC tree; EPSS and CVSS remain visible supporting evidence instead
of silently becoming a new score. Unknown inputs use the official conservative
defaults and are flagged for confirmation.

The implementation is checked offline against all **72 Deployer paths** and
all **16 Human Impact combinations** with `patchtriage verify`. See the
[reviewer validation protocol](docs/VALIDATION.md).

![PatchTriage demo](docs/demo.gif)

## Quick start with Docker

Docker is the shortest path to the GUI:

```bash
git clone https://github.com/d01ki/PatchTriage
cd PatchTriage
./run.sh
```

Open [http://localhost:8765](http://localhost:8765). The equivalent command is:

```bash
docker compose up gui
```

Stop the console with `./run.sh --stop` or `docker compose down`. Targets,
attached evidence, reports, and caches persist in Docker volumes.

To run the bundled air-gapped demonstration instead:

```bash
docker compose run --rm demo
# HTML: ./out/demo_report.html
# JSON: ./out/demo_report.json
```

## Local installation

Python 3.10 or newer is required.

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
# .\.venv\Scripts\Activate.ps1

python -m pip install -e .
patchtriage serve
```

The GUI opens at [http://127.0.0.1:8765](http://127.0.0.1:8765). If the
console script is not on `PATH`, use:

```bash
python -m patchtriage.cli serve
```

Useful entry points:

```bash
patchtriage serve       # GUI
patchtriage demo        # reproducible offline demo
patchtriage start       # guided CLI workflow
patchtriage run --help  # scriptable pipeline
patchtriage verify      # offline conformance and repeatability proof
```

## GUI workflow

1. Add a target that represents one deployed system or service.
2. Record the target's CERT/CC SSVC context.
3. Attach vulnerability evidence.
4. Run the deterministic assessment.
5. Review vulnerability-specific **Exploitation** and **Automatable** values;
   confirm them when the evidence-derived value or conservative default needs
   human review, then rerun.
6. Review the SSVC decision path and package-level remediation action.

The **Attach scan / SBOM** button accepts:

- Trivy JSON;
- Grype JSON;
- osv-scanner JSON;
- CycloneDX JSON SBOM;
- SPDX JSON SBOM.

Scanner JSON already contains vulnerabilities. An SBOM contains components,
not vulnerability findings, so PatchTriage resolves its packages through
[OSV.dev](https://osv.dev) before assessment. That SBOM path therefore needs
network access; the bundled demo does not.

## What target context means

The GUI asks only for organizational inputs that belong to the official SSVC
Deployer method. Describe the deployed target and the credible consequence of
its failure, not the vulnerability itself.

| GUI field | What to assess | CERT/CC values | Default when unknown |
|---|---|---|---|
| System Exposure | How attackers can reach this deployed system | Small, Controlled, Open | Open |
| Mission Impact | Effect on Mission Essential Functions (MEFs) | Degraded, MEF Support Crippled, MEF Failure, Mission Failure | MEF Support Crippled |
| Safety Impact | Highest credible harm to people, systems, environment, finances, or well-being | Negligible, Marginal, Critical, Catastrophic | Marginal |

The SSVC engine evaluates the remaining decision points as follows:

- **Exploitation** is derived from authoritative threat evidence. A CISA KEV
  listing is Active; public exploit evidence can establish Public PoC. The GUI
  lets an analyst confirm or replace the value for each finding.
- **Automatable** is vulnerability-specific. PatchTriage derives it per
  finding from CVSS v4 `AU`. If it is unavailable, the official conservative
  default is Yes and the GUI asks an analyst to confirm or replace the value.
  It is intentionally not a target-wide field.
- **Human Impact** is derived by the published CERT/CC table from the target's
  Mission Impact and Safety Impact.

`Unknown` is a PatchTriage capture state, not an additional SSVC value. The
official conservative default is applied and the inferred field remains
visibly marked for confirmation.

Official definitions:

- [SSVC Deployer decision tree](https://certcc.github.io/SSVC/howto/deployer_tree/)
- [System Exposure](https://certcc.github.io/SSVC/reference/decision_points/system_exposure/)
- [Automatable](https://certcc.github.io/SSVC/reference/decision_points/automatable/)
- [Mission Impact](https://certcc.github.io/SSVC/reference/decision_points/mission_impact/)
- [Safety Impact](https://certcc.github.io/SSVC/reference/decision_points/safety_impact/)
- [Human Impact](https://certcc.github.io/SSVC/reference/decision_points/human_impact/)

## Reading the result

SSVC produces a categorical deployment decision, not a numerical risk score.

| Outcome | Plain-language action | PatchTriage operational target |
|---|---|---:|
| Immediate | Act now | 3 days |
| Out-of-Cycle | Use the next available deployment opportunity | 14 days |
| Scheduled | Include in normal maintenance | 30 days |
| Defer | Monitor and reassess | 90 days |

The day targets are PatchTriage workflow defaults; they are not additional
CERT/CC decision values. Organizations should map them to their own policy.

### Where GUI data is stored

The scan/SBOM upload and generated HTML report are processed on the machine
running PatchTriage and stored under its configuration directory. With Docker
Compose this is the `config` volume mounted at
`/home/patchtriage/.config/patchtriage`.

The web GUI assigns each browser a random HttpOnly session cookie. Targets,
uploads, and reports are stored in a separate server directory for that
anonymous session, so one visitor cannot list or open another visitor's data.
Anonymous session data expires after six hours. Decision summaries shown in
the page live only in that browser tab's memory.

This is anonymous isolation, not user authentication. A person who obtains a
session cookie can access that session, so the public demo should not receive
confidential production scans. Use the local Docker deployment or add an
authentication proxy when assessing sensitive assets.

### Why Scheduled has no SSVC score

That is intentional. A Scheduled result is a complete SSVC outcome, not a
missing calculation. The GUI and HTML report still show:

- the four decision-point values and their evidence sources;
- confidence and any values that need confirmation;
- CVSS;
- EPSS 30-day probability;
- CISA KEV status;
- fixed-version availability;
- vendor advisories and the machine-audit result.

CVSS, EPSS, KEV, and fix availability remain visible as supporting evidence.
Inside the same outcome, the SSVC decision points are compared first, followed
by EPSS and CVSS tie-breakers. No values are added together into a score, and
no tie-breaker can override the categorical outcome.

### What “No vulnerabilities found” means

This state means the attached scan contained zero vulnerability records, or an
attached SBOM resolved to zero known OSV vulnerabilities. It does **not** mean
an SSVC Defer decision and does not prove that the target is vulnerability-free.
Confirm that the scan covered the intended artifact, that the file is current,
and that SBOM package identifiers and versions are complete before relying on
the result.

## Bundled demo

The demo uses frozen Trivy, Grype, EPSS, CISA KEV, and NVD evidence, so it
works without a network or API key. Its three deduplicated findings illustrate
why severity alone is not the deployment decision:

| SSVC outcome | Vulnerability | Package | CVSS | EPSS | CISA KEV |
|---|---|---|---:|---:|---|
| Immediate | CVE-2023-4911 | libc6 | 7.8 | 0.856 | Yes |
| Scheduled | CVE-2024-3094 | xz-utils | 10.0 | 0.372 | No |
| Scheduled | CVE-2021-23337 | lodash | 7.2 | 0.018 | No |

The known-exploited finding is surfaced before the CVSS 10.0 finding, while
the exact outcome remains explainable from the SSVC path and target context.
This small demo proves pipeline behavior, not real-world effectiveness.

## Scriptable usage

```bash
# Scanner output to JSON and self-contained HTML reports
patchtriage run trivy.json grype.json \
  --assets assets.yaml \
  --html report.html \
  -o report.json

# SBOM to assessed findings through OSV.dev
patchtriage run sbom.spdx.json --html report.html

# Enter explicit target context without an inventory
patchtriage run trivy.json \
  --ssvc-exposure open \
  --ssvc-mission-impact mef_failure \
  --ssvc-safety-impact critical

# Skip slower NVD enrichment; retain EPSS and CISA KEV
patchtriage run trivy.json --no-nvd

# Query every vendor connector, or disable vendor advisories
patchtriage run trivy.json --vendor-sources all
patchtriage run trivy.json --no-vendor-advisories
```

An advanced `--ssvc-automatable yes|no` override exists for cases where an
analyst has established the value for the vulnerabilities in that run. Do not
use it as a generic property of the target.

Example `assets.yaml`:

```yaml
assets:
  - match: "web-frontend*"
    system_exposure: open
    mission_impact: mef_failure
    safety_impact: critical
```

Generate inputs with scanners you already use:

```bash
trivy image --format json -o trivy.json myorg/web-frontend:1.4
grype myorg/web-frontend:1.4 -o json > grype.json
osv-scanner --format json -r ./repo > osv.json
```

## Evidence connectors

Core enrichment uses EPSS, CISA KEV, and optionally NVD. Vendor connectors are
selected from package and distribution metadata by default.

| Source | Evidence returned |
|---|---|
| Microsoft MSRC | Update document and CVRF/CSAF reference |
| Red Hat RHSA | Advisory, severity, and released packages |
| Ubuntu USN | Advisory, affected packages, and fixed versions |
| Debian Security Tracker | Distribution release status and fixed versions |
| GitHub GHSA | Advisory, ecosystem packages, patched version, and vulnerable functions |

The connectors work without credentials. `GITHUB_TOKEN`/`GH_TOKEN` and
`NVD_API_KEY` only raise public API rate limits. Connector failures are
recorded per finding and do not abort the assessment.

## Optional AI explanations

Install the additional dependency and provide an Anthropic API key:

```bash
python -m pip install -e ".[ai]"
export ANTHROPIC_API_KEY=...

patchtriage run trivy.json --triage claude --html report.html
patchtriage run trivy.json --triage cascade --html report.html
```

- `rules`: deterministic SSVC only; default and suitable for CI.
- `claude`: deterministic SSVC plus an AI-written explanation.
- `cascade`: screens every result and escalates only urgent, uncertain, or
  audit-failing explanations to the larger configured model.

If an API call fails, the finding falls back to deterministic output. The
audit rejects outcome, action, deadline, or signal claims that conflict with
the evidence.

## Pipeline

```text
scan JSON / SBOM
        |
        v
ingest -> deduplicate -> apply target context -> enrich threat/vendor evidence
        -> SSVC Deployer decision -> machine audit -> remediation plan
        -> JSON + self-contained HTML report
```

Aliases such as CVE and GHSA are merged conservatively. Evidence provenance is
retained in the JSON result. The HTML report has no CDN dependency and can be
opened offline or attached to a review ticket.

## Reproducibility and reviewer verification

Run the current engine's offline proof from a clean checkout:

```bash
python -m pip install -e .
patchtriage verify --repeats 100 --output verification_report.json
```

The verification command checks:

- all 72 published SSVC Deployer decision-table paths;
- all 16 published Human Impact combinations;
- GUI target context reaching the production decision engine unchanged;
- conservative handling of unknown context;
- repeated deterministic decision hashes;
- the frozen end-to-end ingest-to-audit pipeline;
- detection of altered outcomes, actions, deadlines, and decision paths.

The output includes SHA-256 fingerprints for the expectation data, frozen
inputs, engine source, and decisions. Run it twice and compare
`input_fingerprint` and `decision_fingerprint`; timestamps and environment
metadata may differ.

See [docs/VALIDATION.md](docs/VALIDATION.md) for the reviewer protocol. Files
under `benchmarks/` are retained as historical engineering artifacts and are
not evidence of the current SSVC engine's real-world effectiveness.

## Deployment notes

The GUI binds to localhost by default. For a trusted container or platform
service, bind explicitly and supply its assigned port:

```bash
patchtriage serve --host 0.0.0.0 --port 8765 --no-browser
```

Do not use `patchtriage demo` as a web-service start command: it writes a
report and exits, so no port remains open. The production demo at
[patch-triage.com](https://patch-triage.com/) runs the same container entry
point on AWS Lightsail. Place any non-demo internet-facing instance behind the
access controls appropriate for vulnerability and asset data.

## Limits

- PatchTriage does not apply patches.
- It is not a replacement for a vulnerability scanner.
- An empty result is not proof that a target is secure.
- SSVC depends on accurate organizational context and current threat evidence.
- The built-in evaluation compares queue orderings on the supplied inventory;
  it is not independent ground truth for remediation effectiveness.
- Human review remains required for inferred inputs and important deployment
  decisions.

## Development

```bash
python -m pip install -e ".[dev]"
pytest -q
patchtriage verify --repeats 25 --output verification_report.json
```

## License

[Apache License 2.0](LICENSE)
