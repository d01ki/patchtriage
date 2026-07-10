"""SBOM ingestion via OSV.dev.

A software bill of materials (SBOM) lists *components*, not vulnerabilities,
so PatchTriage — a decision layer, not a scanner — cannot triage one directly.
This module turns an SBOM into findings the same way a scanner would, but
online and with no local tooling: it reads a CycloneDX or SPDX file (e.g. the
SPDX export GitHub produces from the dependency graph), extracts each package,
and queries the free OSV.dev API for known vulnerabilities.

This is the path for "I cloned the repo on Linux and my SBOM comes from
GitHub" — no Trivy/Grype install required, just network access to OSV.

Everything OSV returns is cached under the enrichment cache dir, so re-runs
are cheap and offline after the first sync.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from ..models import Asset, Package, RawFinding, Severity
from .parsers import _prefer_cve

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"


# --------------------------------------------------------------- SBOM parsing
def is_sbom(data: dict) -> str | None:
    """Return 'cyclonedx' | 'spdx' if data looks like an SBOM, else None."""
    if data.get("bomFormat") == "CycloneDX" or "components" in data and \
            data.get("specVersion"):
        return "cyclonedx"
    if str(data.get("spdxVersion", "")).startswith("SPDX-") or \
            ("SPDXID" in data and "packages" in data):
        return "spdx"
    return None


def _purl_from_spdx_pkg(pkg: dict) -> str:
    for ref in pkg.get("externalRefs", []) or []:
        if ref.get("referenceType") == "purl" or \
                ref.get("referenceCategory") in ("PACKAGE-MANAGER", "PACKAGE_MANAGER"):
            loc = ref.get("referenceLocator", "")
            if loc.startswith("pkg:"):
                return loc
    return ""


def _components_cyclonedx(data: dict) -> list[Package]:
    out: list[Package] = []

    def walk(comps):
        for c in comps or []:
            name = c.get("name", "")
            if name:
                out.append(Package(
                    name=name,
                    version=c.get("version", ""),
                    purl=c.get("purl", ""),
                    ecosystem=_ecosystem_from_purl(c.get("purl", "")),
                ))
            walk(c.get("components"))  # CycloneDX allows nested components

    walk(data.get("components"))
    return out


def _components_spdx(data: dict) -> list[Package]:
    out: list[Package] = []
    for p in data.get("packages", []) or []:
        name = p.get("name", "")
        if not name:
            continue
        purl = _purl_from_spdx_pkg(p)
        out.append(Package(
            name=name,
            version=p.get("versionInfo", ""),
            purl=purl,
            ecosystem=_ecosystem_from_purl(purl),
        ))
    return out


def _ecosystem_from_purl(purl: str) -> str:
    # pkg:pypi/django@3.2 -> pypi ; pkg:golang/... -> golang
    if purl.startswith("pkg:"):
        rest = purl[4:]
        return rest.split("/", 1)[0].split("@", 1)[0]
    return ""


def parse_sbom_components(data: dict) -> list[Package]:
    kind = is_sbom(data)
    if kind == "cyclonedx":
        return _components_cyclonedx(data)
    if kind == "spdx":
        return _components_spdx(data)
    raise ValueError("not a recognized CycloneDX or SPDX SBOM")


# --------------------------------------------------------------- OSV mapping
def raw_from_osv_vuln(vuln: dict, pkg: Package, asset: Asset) -> RawFinding:
    """Map one OSV vulnerability record onto a RawFinding."""
    vuln_id, aliases = _prefer_cve(vuln.get("id", ""), vuln.get("aliases") or [])

    # earliest fixed version across affected ranges (heuristic, like parse_osv)
    fixed = ""
    for aff in vuln.get("affected") or []:
        for r in aff.get("ranges") or []:
            for ev in r.get("events") or []:
                if "fixed" in ev:
                    fixed = ev["fixed"]

    # OSV sometimes carries a coarse label in database_specific
    sev_label = ""
    for src in (vuln.get("database_specific"), *(
            (aff.get("database_specific") or {})
            for aff in vuln.get("affected") or [])):
        if isinstance(src, dict) and src.get("severity"):
            sev_label = str(src["severity"])
            break

    return RawFinding(
        vuln_id=vuln_id,
        aliases=aliases,
        source_scanner="osv-sbom",
        package=pkg.model_copy(update={"fixed_version": fixed}),
        asset=asset,
        severity=Severity.parse(sev_label),
        title=vuln.get("summary", ""),
        description=(vuln.get("details") or "")[:2000],
        references=[r.get("url", "") for r in (vuln.get("references") or [])][:15],
        raw=vuln,
    )


# --------------------------------------------------------------- OSV lookup
def _osv_cache_load() -> dict:
    from ..enrich.clients import cache_dir
    p = cache_dir() / "osv_vulns.json"
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
    return {}


def _osv_cache_save(cache: dict) -> None:
    from ..enrich.clients import cache_dir
    d = cache_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / "osv_vulns.json").write_text(json.dumps(cache), encoding="utf-8")


def _query_ids(components: list[Package], client: httpx.Client,
               progress=None) -> list[list[str]]:
    """OSV querybatch -> per-component list of vuln ids. Skips purl-less pkgs."""
    queries = []
    for c in components:
        if c.purl:
            queries.append({"package": {"purl": c.purl}})
        elif c.ecosystem and c.name and c.version:
            queries.append({"package": {"name": c.name,
                                        "ecosystem": c.ecosystem},
                            "version": c.version})
        else:
            queries.append(None)  # unqueryable

    ids: list[list[str]] = [[] for _ in queries]
    idx = [i for i, q in enumerate(queries) if q is not None]
    payload = [queries[i] for i in idx]
    for start in range(0, len(payload), 100):
        chunk = payload[start:start + 100]
        chunk_idx = idx[start:start + 100]
        r = client.post(OSV_QUERYBATCH_URL, json={"queries": chunk}, timeout=60)
        r.raise_for_status()
        for local_i, result in enumerate(r.json().get("results") or []):
            vulns = result.get("vulns") or []
            ids[chunk_idx[local_i]] = [v["id"] for v in vulns if v.get("id")]
        if progress:
            progress(min(start + 100, len(payload)), len(payload))
    return ids


def _fetch_vuln(vid: str, client: httpx.Client, cache: dict) -> dict | None:
    if vid in cache:
        return cache[vid] or None
    r = client.get(OSV_VULN_URL + vid, timeout=30)
    entry = r.json() if r.status_code == 200 else {}
    cache[vid] = entry
    return entry or None


def load_sbom(path: str | Path, asset: Asset | None = None,
              progress=None) -> list[RawFinding]:
    """Read an SBOM file and resolve its components to findings via OSV.dev."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    components = parse_sbom_components(data)
    if not components:
        raise ValueError(f"{path}: SBOM parsed but contained no components")

    default_asset = asset or Asset(identifier=Path(path).name, kind="sbom")
    cache = _osv_cache_load()
    findings: list[RawFinding] = []
    with httpx.Client(headers={"user-agent": "patchtriage"}) as client:
        per_component_ids = _query_ids(components, client, progress)
        for pkg, vids in zip(components, per_component_ids):
            for vid in vids:
                vuln = _fetch_vuln(vid, client, cache)
                if vuln:
                    findings.append(raw_from_osv_vuln(vuln, pkg, default_asset))
    _osv_cache_save(cache)
    return findings
