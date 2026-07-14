"""Layer 5 — AI triage.

The LLM never invents scores: it receives the deterministic signals from
Layers 1-3 (severity, CVSS, EPSS, KEV, exploit refs, asset context) and
reasons over them like an analyst, returning structured JSON.

Backends are pluggable. Three are shipped:
  * "rules"   — deterministic baseline (no API key needed, good for CI/demos)
  * "claude"  — Anthropic API (default model: claude-opus-4-8), structured
                output enforced via strict tool use.
  * "cascade" — two-tier agent pipeline: a fast screening model triages every
                finding, and only findings that are high-signal (KEV / high
                EPSS / exposed critical asset) or that fail the machine audit
                are escalated to a frontier model. Frontier reasoning where it
                matters, screening-tier cost everywhere else.

Robustness: run_triage() parallelizes API calls and degrades gracefully —
a finding whose API call fails is triaged by the deterministic rules baseline
and tagged, so a network blip never aborts a 2,000-finding run.
"""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional, Protocol

from ..models import Finding

DEFAULT_MODEL = "claude-opus-4-8"
DEFAULT_SCREEN_MODEL = "claude-haiku-4-5"

TRIAGE_SYSTEM_PROMPT = """\
You are a vulnerability-management analyst performing patch triage.
You will receive ONE finding as JSON containing deterministic signals
(severity, CVSS, EPSS probability, CISA KEV status, exploit references,
fix availability, asset criticality/exposure, reachability/runtime evidence).

Rules:
- NEVER invent or adjust numeric scores. Reason only from the given signals.
- KEV=true or EPSS>0.5 on an internet-exposed asset is almost always P1.
- No available fix => recommend mitigation, not patching.
- Be concise and concrete. Output via the `triage` tool only.
"""

TRIAGE_TOOL = {
    "name": "triage",
    "description": "Record the triage decision for one finding.",
    "strict": True,
    "input_schema": {
        "type": "object",
        "properties": {
            "priority": {"type": "string", "enum": ["P1", "P2", "P3", "P4"]},
            "action": {"type": "string",
                       "enum": ["patch_now", "patch_scheduled",
                                "mitigate", "accept_risk", "investigate"]},
            "rationale": {"type": "string",
                          "description": "2-3 sentences citing the signals"},
            "suggested_deadline_days": {"type": "integer"},
        },
        "required": ["priority", "action", "rationale",
                     "suggested_deadline_days"],
        "additionalProperties": False,
    },
}


class TriageBackend(Protocol):
    def triage(self, finding: Finding) -> dict: ...


# ------------------------------------------------------------------ baseline
class RulesBackend:
    """Deterministic baseline. Also serves as the LLM's sanity reference."""

    def triage(self, f: Finding) -> dict:
        e = f.enrichment
        score = e.nvd_cvss_score or f.cvss_score or 0.0
        epss = e.epss_score or 0.0
        exposed = f.asset.internet_exposed is True
        runtime_relevant = (f.asset.reachable is True
                            or f.asset.runtime_observed is True)
        has_fix = bool(f.package.fixed_version)

        if e.in_cisa_kev or (epss >= 0.5 and (exposed or runtime_relevant)):
            prio, days = "P1", 3 if e.kev_ransomware else 7
        elif epss >= 0.1 or (score >= 9.0 and (exposed or runtime_relevant)):
            prio, days = "P2", 14
        elif score >= 7.0:
            prio, days = "P3", 30
        else:
            prio, days = "P4", 90

        action = ("patch_now" if prio == "P1" and has_fix
                  else "mitigate" if prio == "P1"
                  else "patch_scheduled" if has_fix
                  else "investigate")
        epss_str = f"{e.epss_score:.3f}" if e.epss_score is not None else "n/a"
        return {
            "priority": prio, "action": action,
            "suggested_deadline_days": days,
            "rationale": (f"rules: cvss={score}, epss={epss_str}, "
                          f"kev={e.in_cisa_kev}, exposed={exposed}, "
                          f"reachable={f.asset.reachable}, "
                          f"runtime_observed={f.asset.runtime_observed}, "
                          f"fix={has_fix}"),
            "backend": "rules",
        }


# ------------------------------------------------------------------ Claude
def _make_anthropic_client():
    try:
        import anthropic
    except ImportError as exc:
        raise RuntimeError(
            "The 'claude' backend requires the anthropic SDK: "
            "pip install 'patchtriage[ai]'") from exc
    try:
        return anthropic.Anthropic()
    except Exception as exc:
        raise RuntimeError(
            "Could not create an Anthropic client. Set ANTHROPIC_API_KEY "
            "(export ANTHROPIC_API_KEY=sk-ant-...) and retry.") from exc


def _finding_payload(f: Finding) -> str:
    payload = f.model_dump(mode="json", exclude={"triage", "description"})
    payload["description"] = f.description[:600]
    return json.dumps(payload)


class ClaudeBackend:
    """Anthropic API backend. Requires ANTHROPIC_API_KEY."""

    def __init__(self, model: str = DEFAULT_MODEL):
        self.client = _make_anthropic_client()
        self.model = model

    def triage(self, f: Finding) -> dict:
        resp = self.client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=[{"type": "text", "text": TRIAGE_SYSTEM_PROMPT,
                     "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": _finding_payload(f)}],
            tools=[TRIAGE_TOOL],
            tool_choice={"type": "tool", "name": "triage"},
        )
        for block in resp.content:
            if block.type == "tool_use" and block.name == "triage":
                out = dict(block.input)
                out["backend"] = self.model
                return out
        raise RuntimeError("Claude returned no triage tool_use block")


# ------------------------------------------------------------------ cascade
class CascadeBackend:
    """Two-tier triage: screen everything cheap, escalate what matters.

    Tier 1 (screen): every finding is triaged by a fast screening model.
    Tier 2 (deep):   a finding is re-triaged by the frontier model when it is
      * high-signal — CISA KEV, EPSS >= 0.1, or on an internet-exposed
        critical/high asset (getting these wrong is expensive), or
      * audit-flagged — the screening decision failed the machine audit
        (fabricated number, KEV downgrade, patch-without-fix, or 2+ level
        divergence from the deterministic baseline).

    The escalation decision and its reasons are recorded in the triage output
    so every routing choice is itself auditable.
    """

    def __init__(self,
                 screen_model: str = DEFAULT_SCREEN_MODEL,
                 deep_model: str = DEFAULT_MODEL,
                 screen: Optional[TriageBackend] = None,
                 deep: Optional[TriageBackend] = None):
        self.screen = screen or ClaudeBackend(screen_model)
        self.deep = deep or ClaudeBackend(deep_model)
        self._rules = RulesBackend()

    def _escalation_reasons(self, f: Finding, tentative: dict) -> list[str]:
        from .audit import audit_finding  # deferred: audit imports engine

        reasons: list[str] = []
        e = f.enrichment
        if e.in_cisa_kev:
            reasons.append("kev")
        if (e.epss_score or 0.0) >= 0.1:
            reasons.append("epss>=0.1")
        if (f.asset.internet_exposed
                and f.asset.criticality in ("critical", "high")):
            reasons.append("exposed_high_value_asset")

        prev = f.triage
        f.triage = tentative
        try:
            audit = audit_finding(f, self._rules)
        finally:
            f.triage = prev
        if not audit["verified"]:
            reasons.append("audit_flags:" + ",".join(audit["flags"]))
        return reasons

    def triage(self, f: Finding) -> dict:
        result = self.screen.triage(f)
        reasons = self._escalation_reasons(f, result)
        if reasons:
            result = self.deep.triage(f)
            result["escalated"] = True
            result["escalation_reasons"] = reasons
        else:
            result["escalated"] = False
        return result


def get_backend(name: str = "rules", model: str | None = None,
                escalation_model: str | None = None) -> TriageBackend:
    if name == "rules":
        return RulesBackend()
    if name == "claude":
        return ClaudeBackend(model or DEFAULT_MODEL)
    if name == "cascade":
        return CascadeBackend(screen_model=model or DEFAULT_SCREEN_MODEL,
                              deep_model=escalation_model or DEFAULT_MODEL)
    raise ValueError(f"Unknown triage backend: {name}")


# ------------------------------------------------------------------ runner
def run_triage(findings: list[Finding], backend: TriageBackend,
               progress: Optional[Callable[[int, int], None]] = None,
               jobs: int = 1) -> list[Finding]:
    """Triage every finding in place.

    API-backed runs parallelize across `jobs` workers. A finding whose API
    call fails falls back to the deterministic rules baseline and is tagged
    (backend="rules_fallback") — one flaky request never aborts the run.
    """
    rules = RulesBackend()
    is_rules = isinstance(backend, RulesBackend)

    def _one(f: Finding) -> dict:
        try:
            return backend.triage(f)
        except Exception as exc:
            if is_rules:  # a bug in the baseline should never be masked
                raise
            out = rules.triage(f)
            out["backend"] = "rules_fallback"
            out["error"] = f"{type(exc).__name__}: {exc}"[:300]
            return out

    if jobs <= 1 or is_rules:
        for i, f in enumerate(findings):
            f.triage = _one(f)
            if progress:
                progress(i + 1, len(findings))
    else:
        done = 0
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            for f, result in zip(findings, pool.map(_one, findings)):
                f.triage = result
                done += 1
                if progress:
                    progress(done, len(findings))
    return findings


# ------------------------------------------------------------------ batch
def run_triage_batch(findings: list[Finding], model: str = DEFAULT_MODEL,
                     poll_seconds: float = 15.0,
                     progress: Optional[Callable[[str], None]] = None,
                     ) -> list[Finding]:
    """Triage via the Anthropic Message Batches API — 50% of standard cost.

    Best for large, non-interactive runs (nightly re-triage of a whole
    estate). Most batches complete within an hour; results are keyed by
    custom_id, never by position. Findings whose batch entry errors fall
    back to the rules baseline, same as run_triage().
    """
    client = _make_anthropic_client()
    rules = RulesBackend()

    requests = [{
        "custom_id": f"finding-{i}",
        "params": {
            "model": model,
            "max_tokens": 1024,
            "system": [{"type": "text", "text": TRIAGE_SYSTEM_PROMPT,
                        "cache_control": {"type": "ephemeral"}}],
            "messages": [{"role": "user", "content": _finding_payload(f)}],
            "tools": [TRIAGE_TOOL],
            "tool_choice": {"type": "tool", "name": "triage"},
        },
    } for i, f in enumerate(findings)]

    batch = client.messages.batches.create(requests=requests)
    if progress:
        progress(f"batch {batch.id} submitted ({len(requests)} findings)")

    while True:
        batch = client.messages.batches.retrieve(batch.id)
        if batch.processing_status == "ended":
            break
        if progress:
            progress(f"batch {batch.id}: {batch.processing_status} "
                     f"({batch.request_counts.processing} processing)")
        time.sleep(poll_seconds)

    by_id: dict[str, dict] = {}
    for result in client.messages.batches.results(batch.id):
        if result.result.type == "succeeded":
            for block in result.result.message.content:
                if block.type == "tool_use" and block.name == "triage":
                    out = dict(block.input)
                    out["backend"] = f"{model} (batch)"
                    by_id[result.custom_id] = out

    for i, f in enumerate(findings):
        out = by_id.get(f"finding-{i}")
        if out is None:
            out = rules.triage(f)
            out["backend"] = "rules_fallback"
            out["error"] = "batch entry errored or expired"
        f.triage = out
    return findings
