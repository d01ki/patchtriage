"""Normalization and failure-isolation tests for official vendor feeds."""

import httpx
import pytest

from patchtriage.enrich.vendors import (
    auto_sources,
    enrich_vendor_advisories,
    parse_debian,
    parse_ghsa,
    parse_msrc,
    parse_rhsa,
    parse_sources,
    parse_usn,
)
from patchtriage.models import Asset, Finding, Package

CVE = "CVE-2021-44228"


def _finding(ecosystem="maven", purl="pkg:maven/org.apache.logging.log4j/log4j-core"):
    return Finding(
        key="finding-1", vuln_id=CVE,
        package=Package(name="log4j-core", version="2.14.1",
                        ecosystem=ecosystem, purl=purl),
        asset=Asset(identifier="checkout", kind="repository"),
        cvss_score=10.0,
    )


def _payloads():
    return {
        "msrc": {"value": [{
            "ID": "2021-Dec", "DocumentTitle": "December 2021 Security Updates",
            "InitialReleaseDate": "2021-12-14T08:00:00Z",
            "CvrfUrl": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2021-Dec",
        }]},
        "rhsa": [{
            "RHSA": "RHSA-2021:5206", "severity": "important",
            "released_on": "2021-12-15T00:00:00Z", "CVEs": [CVE],
            "released_packages": ["log4j-core-2.16.0-1.el8"],
        }],
        "usn": {
            "id": f"UBUNTU-{CVE}", "summary": "Log4j vulnerability",
            "published": "2021-12-13T00:00:00Z", "related": ["USN-5192-1"],
            "references": [{"type": "ADVISORY",
                            "url": "https://ubuntu.com/security/notices/USN-5192-1"}],
            "affected": [{
                "package": {"name": "apache-log4j2"},
                "ranges": [{"events": [{"introduced": "0"},
                                         {"fixed": "2.15.0-0.21.04.1"}]}],
            }],
        },
        "debian": {
            "apache-log4j2": {CVE: {
                "description": "Apache Log4j2 remote code execution",
                "releases": {"bookworm": {
                    "status": "resolved", "fixed_version": "2.17.1-1",
                    "urgency": "high",
                }},
            }},
        },
        "ghsa": [{
            "ghsa_id": "GHSA-jfh8-c2jp-5v3q", "cve_id": CVE,
            "html_url": "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q",
            "summary": "Log4Shell", "severity": "critical",
            "published_at": "2021-12-10T00:00:00Z",
            "vulnerabilities": [{
                "package": {"ecosystem": "maven", "name": "log4j-core"},
                "first_patched_version": "2.15.0",
                "vulnerable_functions": ["JndiManager.lookup"],
            }],
        }],
    }


def test_each_official_feed_is_normalized():
    payloads = _payloads()
    assert parse_msrc(payloads["msrc"], CVE)[0]["advisory_id"] == "2021-Dec"
    rhsa = parse_rhsa(payloads["rhsa"], CVE)[0]
    assert rhsa["advisory_id"] == "RHSA-2021:5206"
    assert rhsa["fixed_versions"] == ["log4j-core-2.16.0-1.el8"]
    usn = parse_usn(payloads["usn"], CVE)[0]
    assert usn["advisory_id"] == "USN-5192-1"
    assert "apache-log4j2 2.15.0-0.21.04.1" in usn["fixed_versions"]
    debian = parse_debian(payloads["debian"], CVE)[0]
    assert debian["fixed_versions"] == ["apache-log4j2 bookworm: 2.17.1-1"]
    ghsa = parse_ghsa(payloads["ghsa"], CVE)[0]
    assert ghsa["advisory_id"] == "GHSA-jfh8-c2jp-5v3q"
    assert ghsa["vulnerable_functions"] == ["JndiManager.lookup"]


def test_source_selection_and_validation():
    assert auto_sources(_finding()) == ("ghsa",)
    assert auto_sources(_finding("ubuntu", "pkg:deb/ubuntu/apache-log4j2")) == (
        "usn",)
    assert parse_sources("all") == ("msrc", "rhsa", "usn", "debian", "ghsa")
    with pytest.raises(ValueError, match="unknown vendor source"):
        parse_sources("oracle")
    with pytest.raises(ValueError, match="cannot be combined"):
        parse_sources("auto,ghsa")


def test_all_connectors_attach_evidence_with_one_normalized_model(
        tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))
    payloads = _payloads()

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith(f"/updates/{CVE}"):
            return httpx.Response(200, json=payloads["msrc"])
        if path.endswith("/csaf.json"):
            return httpx.Response(200, json=payloads["rhsa"])
        if path.endswith(f"/vulns/UBUNTU-{CVE}"):
            return httpx.Response(200, json=payloads["usn"])
        if path.endswith("/tracker/data/json"):
            return httpx.Response(200, json=payloads["debian"])
        if path.endswith("/advisories"):
            return httpx.Response(200, json=payloads["ghsa"])
        return httpx.Response(404)

    finding = _finding()
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        summary = enrich_vendor_advisories(
            [finding], sources="all", client=client)
    assert summary == {
        "sources": ["msrc", "rhsa", "usn", "debian", "ghsa"],
        "checked_cves": 1, "advisories": 5, "errors": 0, "truncated": 0,
    }
    assert finding.enrichment.vendor_sources_checked == [
        "msrc", "rhsa", "usn", "debian", "ghsa"]
    assert {a.source for a in finding.enrichment.vendor_advisories} == {
        "msrc", "rhsa", "usn", "debian", "ghsa"}
    assert finding.enrichment.vendor_lookup_errors == []


def test_connector_failure_is_visible_but_non_fatal(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path))

    def unavailable(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"message": "maintenance"})

    finding = _finding()
    with httpx.Client(transport=httpx.MockTransport(unavailable)) as client:
        summary = enrich_vendor_advisories(
            [finding], sources="ghsa", client=client)
    assert summary["errors"] == 1
    assert finding.enrichment.vendor_advisories == []
    assert finding.enrichment.vendor_sources_checked == ["ghsa"]
    assert finding.enrichment.vendor_lookup_errors
