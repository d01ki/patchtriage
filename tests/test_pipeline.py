import json
from pathlib import Path

import pytest

from patchtriage.dedup import dedup
from patchtriage.ingest.parsers import load_file, sniff_format
from patchtriage.models import Asset, Enrichment
from patchtriage.triage.engine import RulesBackend

FIX = Path(__file__).parent / "fixtures"


def _load_all():
    return (load_file(FIX / "trivy_sample.json"),
            load_file(FIX / "grype_sample.json"))


def test_sniff_format():
    assert sniff_format(json.loads((FIX / "trivy_sample.json").read_text())) == "trivy"
    assert sniff_format(json.loads((FIX / "grype_sample.json").read_text())) == "grype"


def test_trivy_parse():
    trivy, _ = _load_all()
    assert len(trivy) == 3
    xz = next(f for f in trivy if f.vuln_id == "CVE-2024-3094")
    assert xz.severity.value == "critical"
    assert xz.cvss_score == 10.0
    assert xz.package.fixed_version.startswith("5.6.1")


def test_grype_ghsa_canonicalized_to_cve():
    _, grype = _load_all()
    lodash = next(f for f in grype if f.package.name == "lodash")
    assert lodash.vuln_id == "CVE-2021-23337"       # CVE preferred over GHSA
    assert "GHSA-35jh-r3h4-6jhm" in lodash.aliases


def test_dedup_merges_cross_scanner():
    trivy, grype = _load_all()
    findings = dedup(trivy + grype)
    # 5 raw -> 3 unique (lodash and libc6 overlap across scanners)
    assert len(findings) == 3
    lodash = next(f for f in findings if f.package.name == "lodash")
    assert sorted(lodash.reported_by) == ["grype", "trivy"]
    libc = next(f for f in findings if "libc" in f.package.name)
    assert sorted(libc.reported_by) == ["grype", "trivy"]
    assert libc.cvss_score == 7.8                    # max kept


def test_rules_backend_kev_is_p1():
    trivy, _ = _load_all()
    findings = dedup(trivy)
    f = findings[0]
    f.asset = Asset(identifier="x", internet_exposed=True)
    f.enrichment = Enrichment(in_cisa_kev=True, epss_score=0.9)
    result = RulesBackend().triage(f)
    assert result["priority"] == "P1"
    assert result["action"] == "patch_now"


def test_rules_backend_low_signal_is_low_priority():
    trivy, _ = _load_all()
    findings = dedup(trivy)
    f = findings[-1]
    f.enrichment = Enrichment(epss_score=0.001, nvd_cvss_score=4.0)
    result = RulesBackend().triage(f)
    assert result["priority"] in ("P3", "P4")


# ---------------------------------------------------------------- new layers
from patchtriage.context import apply_context, load_inventory
from patchtriage.evalcmp import evaluate
from patchtriage.plan import build_plan, finding_risk
from patchtriage.report.html import render_html


def _triaged_findings():
    trivy, grype = _load_all()
    findings = dedup(trivy + grype)
    for f in findings:
        f.asset.internet_exposed = True
        f.asset.criticality = "critical"
    libc = next(f for f in findings if "libc" in f.package.name)
    libc.enrichment = Enrichment(in_cisa_kev=True, kev_ransomware=True,
                                 epss_score=0.856, nvd_cvss_score=7.8)
    xz = next(f for f in findings if f.package.name == "xz-utils")
    xz.enrichment = Enrichment(epss_score=0.372, nvd_cvss_score=10.0)
    lodash = next(f for f in findings if f.package.name == "lodash")
    lodash.enrichment = Enrichment(epss_score=0.018, nvd_cvss_score=7.2)
    from patchtriage.triage.engine import RulesBackend, run_triage
    return run_triage(findings, RulesBackend())


def test_context_apply(tmp_path):
    inv = tmp_path / "assets.yaml"
    inv.write_text(
        "assets:\n  - match: 'web-frontend*'\n    criticality: critical\n"
        "    internet_exposed: true\n")
    trivy, _ = _load_all()
    findings = dedup(trivy)
    n = apply_context(findings, load_inventory(inv))
    assert n == len(findings)
    assert all(f.asset.criticality == "critical" for f in findings)
    assert all(f.asset.internet_exposed for f in findings)


def test_plan_ranks_kev_action_first():
    findings = _triaged_findings()
    actions = build_plan(findings)
    assert actions[0].package == "libc6"          # KEV beats CVSS 10.0
    assert actions[0].kev_count == 1
    assert actions[0].kind == "upgrade"
    assert "2.36-9+deb12u3" in actions[0].summary


def test_finding_risk_kev_dominates():
    findings = _triaged_findings()
    libc = next(f for f in findings if "libc" in f.package.name)
    xz = next(f for f in findings if f.package.name == "xz-utils")
    assert finding_risk(libc) > finding_risk(xz)


def test_eval_patchtriage_beats_cvss_at_k1():
    findings = _triaged_findings()
    rows = evaluate(findings, budgets=[1])
    assert rows[0].kev_baseline == 0              # CVSS order misses the KEV
    assert rows[0].kev_patchtriage == 1           # we catch it
    assert rows[0].epss_patchtriage > rows[0].epss_baseline


def test_html_report_renders():
    findings = _triaged_findings()
    actions = build_plan(findings)
    html = render_html(findings, actions, evaluate(findings))
    assert "<!doctype html>" in html
    assert "CVE-2023-4911" in html
    assert "Remediation plan" in html
    assert "cdn" not in html.lower()              # must stay self-contained


# ---------------------------------------------------------------- audit layer
from patchtriage.triage.audit import audit_all, audit_finding
from patchtriage.triage.engine import RulesBackend as _RB


def test_audit_verifies_clean_decisions():
    findings = _triaged_findings()
    summary = audit_all(findings)
    assert summary["verified"] == summary["total"] == len(findings)
    assert all(f.triage["audit"]["verified"] for f in findings)


def test_audit_catches_fabricated_number():
    findings = _triaged_findings()
    f = findings[0]
    f.triage["rationale"] = "EPSS of 0.99 demands urgency."   # real epss differs
    result = audit_finding(f, _RB())
    assert not result["verified"]
    assert any(fl.startswith("fabricated_number") for fl in result["flags"])


def test_audit_catches_kev_downgrade():
    findings = _triaged_findings()
    libc = next(f for f in findings if "libc" in f.package.name)
    libc.triage["priority"] = "P4"
    libc.triage["rationale"] = "seems fine"
    result = audit_finding(libc, _RB())
    assert "kev_downgraded" in result["flags"]
    assert any(fl.startswith("baseline_divergence") for fl in result["flags"])


def test_audit_catches_patch_without_fix():
    findings = _triaged_findings()
    f = findings[0]
    f.package.fixed_version = ""
    f.triage["action"] = "patch_now"
    f.triage["rationale"] = "patch it"
    result = audit_finding(f, _RB())
    assert "patch_without_fix" in result["flags"]


# ---------------------------------------------------------------- sbom guard
def test_sbom_input_gets_helpful_error(tmp_path):
    spdx = tmp_path / "sbom.json"
    spdx.write_text('{"spdxVersion": "SPDX-2.3", "packages": []}',
                    encoding="utf-8")
    with pytest.raises(ValueError, match="SPDX SBOM") as exc:
        load_file(spdx)
    assert "trivy sbom" in str(exc.value)      # remediation hint included
    cdx = tmp_path / "bom.json"
    cdx.write_text('{"bomFormat": "CycloneDX", "components": []}',
                   encoding="utf-8")
    with pytest.raises(ValueError, match="CycloneDX SBOM"):
        load_file(cdx)
