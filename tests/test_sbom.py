"""SBOM ingestion: format detection, component extraction, OSV mapping.

Network is not exercised here — OSV lookup is covered by mapping a canned
OSV vulnerability record onto a RawFinding.
"""

import json
from pathlib import Path

from patchtriage.ingest.parsers import detect_sbom, load_file
from patchtriage.ingest.sbom import (is_sbom, parse_sbom_components,
                                      raw_from_osv_vuln)
from patchtriage.models import Asset, Package

FIX = Path(__file__).parent / "fixtures"


def _load(name):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


def test_detects_cyclonedx_and_spdx():
    assert is_sbom(_load("sbom_cyclonedx.json")) == "cyclonedx"
    assert is_sbom(_load("sbom_spdx.json")) == "spdx"
    assert detect_sbom(_load("sbom_spdx.json")) == "SPDX"
    # a scanner file is not an SBOM
    assert is_sbom(_load("trivy_sample.json")) is None


def test_cyclonedx_components_including_nested():
    comps = parse_sbom_components(_load("sbom_cyclonedx.json"))
    names = {c.name for c in comps}
    assert names == {"lodash", "django", "sqlparse"}  # nested picked up
    django = next(c for c in comps if c.name == "django")
    assert django.version == "3.2.0"
    assert django.ecosystem == "pypi"          # derived from purl
    assert django.purl == "pkg:pypi/django@3.2.0"


def test_spdx_components_and_purl_from_externalrefs():
    comps = parse_sbom_components(_load("sbom_spdx.json"))
    names = {c.name for c in comps}
    assert names == {"lodash", "django"}
    lodash = next(c for c in comps if c.name == "lodash")
    assert lodash.purl == "pkg:npm/lodash@4.17.20"
    assert lodash.ecosystem == "npm"


def test_osv_vuln_maps_to_raw_finding_with_cve_and_fix():
    vuln = {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "aliases": ["CVE-2021-23337"],
        "summary": "Command injection in lodash",
        "details": "long description",
        "severity": [{"type": "CVSS_V3",
                      "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [{"ranges": [{"type": "SEMVER",
                                  "events": [{"introduced": "0"},
                                             {"fixed": "4.17.21"}]}],
                      "database_specific": {"severity": "HIGH"}}],
        "references": [{"url": "https://example.com/advisory"}],
    }
    pkg = Package(name="lodash", version="4.17.20", ecosystem="npm")
    asset = Asset(identifier="demo-app", kind="sbom")
    raw = raw_from_osv_vuln(vuln, pkg, asset)
    assert raw.vuln_id == "CVE-2021-23337"          # CVE preferred over GHSA
    assert "GHSA-xxxx-yyyy-zzzz" in raw.aliases
    assert raw.package.fixed_version == "4.17.21"    # from affected ranges
    assert raw.severity.value == "high"             # from database_specific
    assert raw.source_scanner == "osv-sbom"


def test_load_file_routes_sbom(monkeypatch):
    """load_file should dispatch SBOMs to the OSV resolver, not the parsers."""
    called = {}

    def fake_load_sbom(path, asset=None, progress=None):
        called["path"] = str(path)
        return []

    import patchtriage.ingest.sbom as sbom
    monkeypatch.setattr(sbom, "load_sbom", fake_load_sbom)
    load_file(FIX / "sbom_spdx.json")
    assert called["path"].endswith("sbom_spdx.json")
