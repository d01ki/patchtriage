"""Layer 3 — Deterministic enrichment.

Three authoritative sources, all free, no API key required (NVD key optional
for higher rate limits):

  * EPSS  (FIRST.org)      probability a CVE is exploited in the next 30 days
  * CISA KEV               catalog of vulnerabilities known-exploited in the wild
  * NVD                    official CVSS score/vector + CWE

Design rules:
  - These values are ground truth. The LLM (Layer 5) consumes them, never
    produces them.
  - Everything is cached on disk (~/.cache/patchtriage) so re-runs are cheap
    and the tool works offline after a first sync.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

from ..models import Finding

CACHE_DIR = Path.home() / ".cache" / "patchtriage"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_EXPLOIT_HINTS = ("exploit-db.com", "metasploit", "github.com/rapid7",
                  "packetstormsecurity", "poc")


def _cache_path(name: str) -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / name


def _load_cache(name: str, max_age_hours: float) -> dict | None:
    p = _cache_path(name)
    if p.exists() and (time.time() - p.stat().st_mtime) < max_age_hours * 3600:
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None
    return None


def _save_cache(name: str, data: dict) -> None:
    _cache_path(name).write_text(json.dumps(data), encoding="utf-8")


# ------------------------------------------------------------------ EPSS
def fetch_epss(cves: list[str], client: httpx.Client) -> dict[str, dict]:
    """Batch EPSS lookup. Returns {cve: {epss, percentile}}."""
    cache = _load_cache("epss.json", max_age_hours=24) or {}
    missing = [c for c in cves if c not in cache]
    for i in range(0, len(missing), 100):  # API accepts comma-separated batches
        batch = missing[i:i + 100]
        r = client.get(EPSS_URL, params={"cve": ",".join(batch)}, timeout=30)
        r.raise_for_status()
        for row in r.json().get("data", []):
            cache[row["cve"]] = {
                "epss": float(row["epss"]),
                "percentile": float(row["percentile"]),
            }
        for c in batch:  # negative-cache CVEs EPSS doesn't know
            cache.setdefault(c, {})
    _save_cache("epss.json", cache)
    return cache


# ------------------------------------------------------------------ CISA KEV
def fetch_kev(client: httpx.Client) -> dict[str, dict]:
    """Full KEV catalog as {cve: entry}. Cached 24h."""
    cache = _load_cache("kev.json", max_age_hours=24)
    if cache is None:
        r = client.get(KEV_URL, timeout=60, follow_redirects=True)
        r.raise_for_status()
        cache = {e["cveID"]: e for e in r.json().get("vulnerabilities", [])}
        _save_cache("kev.json", cache)
    return cache


# ------------------------------------------------------------------ NVD
def fetch_nvd(cve: str, client: httpx.Client, api_key: str | None = None) -> dict:
    """Single-CVE NVD lookup (per-CVE cache; NVD rate limits are strict)."""
    cache = _load_cache("nvd.json", max_age_hours=24 * 7) or {}
    if cve in cache:
        return cache[cve]
    headers = {"apiKey": api_key} if api_key else {}
    r = client.get(NVD_URL, params={"cveId": cve}, headers=headers, timeout=30)
    if r.status_code == 403:  # rate limited — back off once
        time.sleep(6)
        r = client.get(NVD_URL, params={"cveId": cve}, headers=headers, timeout=30)
    entry: dict = {}
    if r.status_code == 200:
        vulns = r.json().get("vulnerabilities", [])
        if vulns:
            cve_obj = vulns[0]["cve"]
            metrics = cve_obj.get("metrics", {})
            for ver in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(ver):
                    d = metrics[ver][0]["cvssData"]
                    entry = {
                        "score": d.get("baseScore"),
                        "vector": d.get("vectorString", ""),
                        "version": d.get("version", ""),
                    }
                    break
            entry["cwes"] = [
                desc["value"]
                for w in cve_obj.get("weaknesses", [])
                for desc in w.get("description", [])
                if desc.get("value", "").startswith("CWE-")
            ]
            entry["references"] = [ref.get("url", "")
                                   for ref in cve_obj.get("references", [])]
    cache[cve] = entry
    _save_cache("nvd.json", cache)
    if not api_key:
        time.sleep(0.7)  # stay under NVD's unauthenticated rate limit
    return entry


# ------------------------------------------------------------------ Orchestrator
def enrich(findings: list[Finding], nvd_api_key: str | None = None,
           use_nvd: bool = True, progress=None) -> list[Finding]:
    """Attach EPSS / KEV / NVD data to every Finding in place."""
    cves = sorted({f.vuln_id for f in findings if f.vuln_id.startswith("CVE-")})
    now = datetime.now(timezone.utc)
    with httpx.Client() as client:
        epss = fetch_epss(cves, client)
        kev = fetch_kev(client)
        for i, f in enumerate(findings):
            e = f.enrichment
            e.enriched_at = now
            if not f.vuln_id.startswith("CVE-"):
                continue
            row = epss.get(f.vuln_id) or {}
            e.epss_score = row.get("epss")
            e.epss_percentile = row.get("percentile")
            e.sources.append("epss")
            k = kev.get(f.vuln_id)
            if k:
                e.in_cisa_kev = True
                e.kev_ransomware = (k.get("knownRansomwareCampaignUse", "")
                                    .lower() == "known")
                e.kev_due_date = k.get("dueDate")
            e.sources.append("kev")
            if use_nvd:
                n = fetch_nvd(f.vuln_id, client, nvd_api_key)
                e.nvd_cvss_score = n.get("score")
                e.nvd_cvss_vector = n.get("vector", "")
                e.nvd_cvss_version = n.get("version", "")
                e.cwe_ids = n.get("cwes", [])
                e.exploit_references = [
                    u for u in n.get("references", [])
                    if any(h in u.lower() for h in _EXPLOIT_HINTS)
                ][:5]
                e.sources.append("nvd")
            if progress:
                progress(i + 1, len(findings))
    return findings
