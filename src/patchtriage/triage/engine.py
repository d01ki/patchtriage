"""Layer 5 — AI triage.

The deterministic CERT/CC SSVC Deployer tree owns action timing. The LLM
receives that final assessment and may add explanation, remediation steps,
and uncertainty notes; it cannot rescore or override the decision.

Backends are pluggable. Three are shipped:
  * "rules"   — compatibility name for deterministic SSVC (no API key)
  * "claude"  — Anthropic API (default model: claude-opus-4-8), structured
                output enforced via strict tool use.
  * "cascade" — two-tier agent pipeline: a fast screening model triages every
                finding; urgent or low-confidence SSVC decisions and failed
                explanation audits are escalated to a frontier model.

Robustness: run_triage() parallelizes API calls and degrades gracefully —
a finding whose API call fails is triaged by the deterministic SSVC baseline
and tagged, so a network blip never aborts a 2,000-finding run.
"""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional, Protocol

from ..models import Finding
from ..ssvc import assess, triage_from_assessment

DEFAULT_MODEL = "claude-opus-4-8"
DEFAULT_SCREEN_MODEL = "claude-haiku-4-5"

TRIAGE_SYSTEM_PROMPT = """\
You are a vulnerability-management analyst performing patch triage.
You will receive ONE finding plus a deterministic SSVC Deployer assessment.
The SSVC decision and P1-P4 mapping are final. Your role is to explain that
decision and propose concrete remediation steps, not to rescore the finding.

Rules:
- NEVER invent or adjust numeric scores. Reason only from the given signals.
- NEVER change the supplied SSVC decision, priority, or service-level target.
- Distinguish observed exploitation (KEV/PoC) from predictive EPSS evidence.
- No available fix means mitigation or investigation, not patching.
- Call out low-confidence SSVC inputs that need human confirmation.
- Be concise and concrete. Output via the `triage` tool only.
"""

TRIAGE_TOOL = {
    "name": "triage",
    "description": "Record the triage decision for one finding.",
    "strict": True,
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {"type": "string",
                       "enum": ["patch_immediately", "patch_out_of_cycle",
                                "patch_scheduled", "mitigate", "monitor",
                                "investigate"]},
            "rationale": {"type": "string",
                          "description": "2-3 sentences citing SSVC inputs"},
            "remediation_steps": {
                "type": "array", "items": {"type": "string"},
                "maxItems": 5,
            },
            "uncertainties": {
                "type": "array", "items": {"type": "string"},
                "maxItems": 5,
            },
        },
        "required": ["action", "rationale", "remediation_steps",
                     "uncertainties"],
        "additionalProperties": False,
    },
}


class TriageBackend(Protocol):
    def triage(self, finding: Finding) -> dict: ...


# ------------------------------------------------------------------ baseline
class SSVCBackend:
    """Deterministic CERT/CC SSVC Deployer decision backend."""

    def triage(self, f: Finding) -> dict:
        return triage_from_assessment(assess(f), backend="ssvc")


class RulesBackend(SSVCBackend):
    """Backward-compatible name for the deterministic SSVC backend."""


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
    payload["ssvc_assessment"] = assess(f).model_dump(mode="json")
    return json.dumps(payload)


def _merge_ai_recommendation(f: Finding, recommendation: dict,
                             backend: str) -> dict:
    """Keep the SSVC decision authoritative and attach AI assistance."""
    result = triage_from_assessment(assess(f), backend=backend)
    if recommendation.get("rationale"):
        result["rationale"] = str(recommendation["rationale"])
    result["ai_recommendation"] = {
        "action": recommendation.get("action"),
        "remediation_steps": recommendation.get("remediation_steps", []),
        "uncertainties": recommendation.get("uncertainties", []),
    }
    return result


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
                return _merge_ai_recommendation(f, out, self.model)
        raise RuntimeError("Claude returned no triage tool_use block")


# ------------------------------------------------------------------ cascade
class CascadeBackend:
    """Two-tier triage: screen everything cheap, escalate what matters.

    Tier 1 (screen): every finding is triaged by a fast screening model.
    Tier 2 (deep):   a finding is re-triaged by the frontier model when it is
      * SSVC-urgent — Immediate or Out-of-Cycle needs richer guidance,
      * context-uncertain — a conservative SSVC input needs confirmation, or
      * audit-flagged — the screening explanation failed the machine audit.

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
        assessment = assess(f)
        if assessment.priority in ("P1", "P2"):
            reasons.append(f"ssvc_{assessment.decision.value}")
        if assessment.needs_confirmation:
            reasons.append(
                "ssvc_confirmation:" + ",".join(assessment.needs_confirmation))

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
    call fails falls back to the deterministic SSVC baseline and is tagged
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
    back to the SSVC baseline, same as run_triage().
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
                    by_id[result.custom_id] = dict(block.input)

    for i, f in enumerate(findings):
        out = by_id.get(f"finding-{i}")
        if out is None:
            out = rules.triage(f)
            out["backend"] = "rules_fallback"
            out["error"] = "batch entry errored or expired"
        else:
            out = _merge_ai_recommendation(f, out, f"{model} (batch)")
        f.triage = out
    return findings
