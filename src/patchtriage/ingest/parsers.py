"""Layer 1 — Ingestion.

Each parser takes a scanner's native JSON output and yields RawFinding objects
in the common schema. Adding a new scanner = adding one function here and
registering it in PARSERS.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable, Iterator

from ..models import Asset, Package, RawFinding, Severity


def _prefer_cve(primary: str, aliases: list[str]) -> tuple[str, list[str]]:
    """Canonicalize on a CVE id when one exists among id+aliases."""
    ids = [primary, *aliases]
    cves = [i for i in ids if i.upper().startswith("CVE-")]
    if cves:
        canonical = sorted(cves)[0].upper()
        rest = [i for i in ids if i.upper() != canonical]
        return canonical, sorted(set(rest))
    return primary, sorted(set(aliases))


# --------------------------------------------------------------------------- Trivy
def parse_trivy(data: dict, default_asset: Asset | None = None) -> Iterator[RawFinding]:
    """Trivy JSON (schema v2, `trivy image --format json`)."""
    artifact = data.get("ArtifactName", "unknown")
    artifact_type = data.get("ArtifactType", "unknown")
    asset = default_asset or Asset(
        identifier=artifact,
        kind="container_image" if artifact_type == "container_image" else artifact_type,
    )
    for result in data.get("Results", []) or []:
        for v in result.get("Vulnerabilities", []) or []:
            vuln_id, aliases = _prefer_cve(v.get("VulnerabilityID", ""), [])
            cvss_score = None
            for src in (v.get("CVSS") or {}).values():
                for k in ("V3Score", "V40Score", "V2Score"):
                    if src.get(k) is not None:
                        cvss_score = max(cvss_score or 0.0, float(src[k]))
            yield RawFinding(
                vuln_id=vuln_id,
                aliases=aliases,
                source_scanner="trivy",
                package=Package(
                    name=v.get("PkgName", ""),
                    version=v.get("InstalledVersion", ""),
                    purl=(v.get("PkgIdentifier") or {}).get("PURL", ""),
                    ecosystem=result.get("Type", ""),
                    fixed_version=v.get("FixedVersion", ""),
                ),
                asset=asset,
                severity=Severity.parse(v.get("Severity")),
                cvss_score=cvss_score,
                title=v.get("Title", ""),
                description=(v.get("Description") or "")[:2000],
                references=(v.get("References") or [])[:15],
                raw=v,
            )


# --------------------------------------------------------------------------- Grype
def parse_grype(data: dict, default_asset: Asset | None = None) -> Iterator[RawFinding]:
    """Grype JSON (`grype -o json`)."""
    src = data.get("source") or {}
    target = src.get("target")
    if isinstance(target, dict):
        identifier = target.get("userInput") or target.get("imageID", "unknown")
    else:
        identifier = str(target or "unknown")
    asset = default_asset or Asset(identifier=identifier, kind=src.get("type", "unknown"))

    for m in data.get("matches", []) or []:
        vuln = m.get("vulnerability") or {}
        related = [r.get("id", "") for r in (m.get("relatedVulnerabilities") or [])]
        vuln_id, aliases = _prefer_cve(vuln.get("id", ""), [r for r in related if r])
        art = m.get("artifact") or {}
        cvss_score = None
        cvss_all = vuln.get("cvss") or []
        for rv in m.get("relatedVulnerabilities") or []:
            cvss_all += rv.get("cvss") or []
        for c in cvss_all:
            val = (c.get("metrics") or {}).get("baseScore")
            if val is not None:
                cvss_score = max(cvss_score or 0.0, float(val))
        fix = vuln.get("fix") or {}
        fixed_versions = fix.get("versions") or []
        yield RawFinding(
            vuln_id=vuln_id,
            aliases=aliases,
            source_scanner="grype",
            package=Package(
                name=art.get("name", ""),
                version=art.get("version", ""),
                purl=art.get("purl", ""),
                ecosystem=art.get("type", ""),
                fixed_version=fixed_versions[0] if fixed_versions else "",
            ),
            asset=asset,
            severity=Severity.parse(vuln.get("severity")),
            cvss_score=cvss_score,
            description=(vuln.get("description") or "")[:2000],
            references=[vuln.get("dataSource", "")] if vuln.get("dataSource") else [],
            raw=m,
        )


# --------------------------------------------------------------------------- OSV
def parse_osv(data: dict, default_asset: Asset | None = None) -> Iterator[RawFinding]:
    """osv-scanner JSON (`osv-scanner --format json`)."""
    for res in data.get("results", []) or []:
        source_path = (res.get("source") or {}).get("path", "unknown")
        asset = default_asset or Asset(identifier=source_path, kind="repository")
        for p in res.get("packages", []) or []:
            pkg = p.get("package") or {}
            for v in p.get("vulnerabilities", []) or []:
                vuln_id, aliases = _prefer_cve(v.get("id", ""), v.get("aliases") or [])
                sev_score = None
                for s in v.get("severity") or []:
                    if s.get("type", "").startswith("CVSS"):
                        # OSV carries vectors; keep raw score out, NVD enrich will fill it
                        pass
                fixed = ""
                for aff in v.get("affected") or []:
                    for r in aff.get("ranges") or []:
                        for ev in r.get("events") or []:
                            if "fixed" in ev:
                                fixed = ev["fixed"]
                yield RawFinding(
                    vuln_id=vuln_id,
                    aliases=aliases,
                    source_scanner="osv",
                    package=Package(
                        name=pkg.get("name", ""),
                        version=pkg.get("version", ""),
                        ecosystem=(pkg.get("ecosystem") or "").lower(),
                        fixed_version=fixed,
                    ),
                    asset=asset,
                    severity=Severity.UNKNOWN,  # OSV has no simple label; NVD fills in
                    cvss_score=sev_score,
                    title=v.get("summary", ""),
                    description=(v.get("details") or "")[:2000],
                    references=[r.get("url", "") for r in (v.get("references") or [])][:15],
                    raw=v,
                )


PARSERS: dict[str, Callable[..., Iterator[RawFinding]]] = {
    "trivy": parse_trivy,
    "grype": parse_grype,
    "osv": parse_osv,
}


def sniff_format(data: dict) -> str | None:
    """Best-effort detection of which scanner produced this JSON."""
    if "Results" in data and ("ArtifactName" in data or "SchemaVersion" in data):
        return "trivy"
    if "matches" in data and "descriptor" in data:
        return "grype"
    if "results" in data and any("packages" in r for r in data.get("results", []) or [{}]):
        return "osv"
    return None


def load_file(path: str | Path, fmt: str | None = None,
              asset: Asset | None = None) -> list[RawFinding]:
    """Load one scanner output file into RawFindings."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    fmt = fmt or sniff_format(data)
    if fmt not in PARSERS:
        raise ValueError(f"Unrecognized scanner format for {path}. "
                         f"Pass fmt= one of {sorted(PARSERS)}")
    return list(PARSERS[fmt](data, asset))
