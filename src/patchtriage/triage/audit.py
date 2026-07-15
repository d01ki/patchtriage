"""Triage audit — the verifiability layer.

Every AI triage decision is machine-checked against the deterministic signals
it was given. This is the tool's core claim: the LLM reasons, but it cannot
fabricate, and you don't have to trust it — you can verify it.

Checks per finding:
  fabricated_numbers   decimal values cited in the rationale must correspond
                       to real signals (EPSS, CVSS) within tolerance
  ssvc_consistency     priority and outcome must match the deterministic SSVC
                       Deployer decision table
  fix_consistency      "patch_*" actions require an available fixed version;
                       "mitigate" is for findings without one
  evidence_completeness the SSVC path and confidence provenance must be present

The result is attached to finding.triage["audit"] and surfaced in the CLI
summary and the HTML report.
"""

from __future__ import annotations

import re

from ..models import Finding
from .engine import RulesBackend

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
    # 1. fabricated numbers
    rationale = _strip_known_tokens(f, t.get("rationale", ""))
    signals = _signal_values(f)
    for m in _DECIMAL.finditer(rationale):
        v = float(m.group())
        if v > 10.0 or v == 0.0:  # not a score-like value / carries no signal
            continue
        if not any(abs(v - s) <= 0.051 for s in signals):
            flags.append(f"fabricated_number:{v}")

    # 2. deterministic SSVC decision respected. KEV is an input to
    # Exploitation=Active, not a shortcut that bypasses stakeholder context.
    baseline = rules.triage(f)
    if t.get("priority") != baseline["priority"]:
        flags.append(
            f"ssvc_priority_mismatch:{baseline['priority']}->{t.get('priority')}")
    if t.get("action") != baseline["action"]:
        flags.append(
            f"ssvc_action_mismatch:{baseline['action']}->{t.get('action')}")
    if t.get("suggested_deadline_days") != baseline["suggested_deadline_days"]:
        flags.append(
            "ssvc_deadline_mismatch:"
            f"{baseline['suggested_deadline_days']}->"
            f"{t.get('suggested_deadline_days')}")
    actual_ssvc = t.get("ssvc")
    expected_ssvc = baseline["ssvc"]
    if not isinstance(actual_ssvc, dict):
        flags.append("ssvc_missing")
    else:
        if actual_ssvc.get("model") != expected_ssvc["model"]:
            flags.append("ssvc_model_mismatch")
        if actual_ssvc.get("decision") != expected_ssvc["decision"]:
            flags.append(
                "ssvc_decision_mismatch:"
                f"{expected_ssvc['decision']}->{actual_ssvc.get('decision')}")
        if actual_ssvc.get("decision_path") != expected_ssvc["decision_path"]:
            flags.append("ssvc_path_mismatch")
        for key in (
            "exploitation", "system_exposure", "automatable",
            "mission_impact", "safety_impact", "human_impact",
        ):
            actual_point = actual_ssvc.get(key)
            expected_point = expected_ssvc[key]
            if not isinstance(actual_point, dict):
                flags.append(f"ssvc_evidence_missing:{key}")
                continue
            if actual_point.get("value") != expected_point["value"]:
                flags.append(f"ssvc_input_mismatch:{key}")
            if not actual_point.get("source") or not actual_point.get("confidence"):
                flags.append(f"ssvc_evidence_missing:{key}")

    # 3. fix consistency
    action = t.get("action", "")
    has_fix = bool(f.package.fixed_version)
    if action.startswith("patch") and not has_fix:
        flags.append("patch_without_fix")
    if action == "mitigate" and has_fix and t.get("priority") in ("P1", "P2"):
        flags.append("mitigate_despite_available_fix")

    return {
        "verified": not flags,
        "flags": flags,
        "baseline_priority": baseline["priority"],
        "ssvc_decision": expected_ssvc["decision"],
        "checks": ["fabricated_numbers", "ssvc_consistency",
                   "fix_consistency", "evidence_completeness"],
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
