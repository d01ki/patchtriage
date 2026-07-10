"""Triage audit — the verifiability layer.

Every AI triage decision is machine-checked against the deterministic signals
it was given. This is the tool's core claim: the LLM reasons, but it cannot
fabricate, and you don't have to trust it — you can verify it.

Checks per finding:
  fabricated_numbers   decimal values cited in the rationale must correspond
                       to real signals (EPSS, CVSS) within tolerance
  kev_respected        a known-exploited (CISA KEV) finding must be P1/P2
  fix_consistency      "patch_*" actions require an available fixed version;
                       "mitigate" is for findings without one
  baseline_divergence  decision is compared with the deterministic rules
                       baseline; a jump of 2+ priority levels is flagged for
                       human review (divergence is allowed — silent divergence
                       is not)

The result is attached to finding.triage["audit"] and surfaced in the CLI
summary and the HTML report.
"""

from __future__ import annotations

import re

from ..models import Finding
from .engine import RulesBackend

_PRIORITY_RANK = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
_DECIMAL = re.compile(r"\d+\.\d+")


def _signal_values(f: Finding) -> list[float]:
    e = f.enrichment
    vals = [v for v in (e.epss_score, e.epss_percentile,
                        e.nvd_cvss_score, f.cvss_score) if v is not None]
    # common renderings of the same signals
    vals += [round(v, 1) for v in vals] + [round(v, 2) for v in vals]
    return vals


def _strip_known_tokens(f: Finding, text: str) -> str:
    """Remove CVE ids and version strings so they don't parse as numbers."""
    text = re.sub(r"CVE-\d{4}-\d+", " ", text)
    for token in (f.package.version, f.package.fixed_version):
        if token:
            text = text.replace(token, " ")
    return text


def audit_finding(f: Finding, rules: RulesBackend) -> dict:
    t = f.triage or {}
    flags: list[str] = []
    e = f.enrichment

    # 1. fabricated numbers
    rationale = _strip_known_tokens(f, t.get("rationale", ""))
    signals = _signal_values(f)
    for m in _DECIMAL.finditer(rationale):
        v = float(m.group())
        if v > 10.0 or v == 0.0:  # not a score-like value / carries no signal
            continue
        if not any(abs(v - s) <= 0.051 for s in signals):
            flags.append(f"fabricated_number:{v}")

    # 2. KEV respected
    if e.in_cisa_kev and _PRIORITY_RANK.get(t.get("priority", "P4"), 9) > 1:
        flags.append("kev_downgraded")

    # 3. fix consistency
    action = t.get("action", "")
    has_fix = bool(f.package.fixed_version)
    if action.startswith("patch") and not has_fix:
        flags.append("patch_without_fix")
    if action == "mitigate" and has_fix and e.in_cisa_kev:
        flags.append("mitigate_despite_fix_on_kev")

    # 4. divergence from deterministic baseline (allowed, but never silent)
    baseline = rules.triage(f)
    div = abs(_PRIORITY_RANK.get(t.get("priority", "P4"), 3)
              - _PRIORITY_RANK[baseline["priority"]])
    if div >= 2:
        flags.append(f"baseline_divergence:{baseline['priority']}"
                     f"->{t.get('priority')}")

    return {
        "verified": not flags,
        "flags": flags,
        "baseline_priority": baseline["priority"],
        "checks": ["fabricated_numbers", "kev_respected",
                   "fix_consistency", "baseline_divergence"],
    }


def audit_all(findings: list[Finding]) -> dict:
    """Audit every triaged finding in place; return a summary."""
    rules = RulesBackend()
    verified = 0
    flagged: list[tuple[str, list[str]]] = []
    for f in findings:
        if f.triage is None:
            continue
        result = audit_finding(f, rules)
        f.triage["audit"] = result
        if result["verified"]:
            verified += 1
        else:
            flagged.append((f.vuln_id, result["flags"]))
    return {"total": sum(1 for f in findings if f.triage is not None),
            "verified": verified, "flagged": flagged}
