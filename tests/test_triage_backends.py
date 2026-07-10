"""Backend-level tests: cascade escalation routing and graceful fallback.

These use injected fake backends — no API key, no network.
"""

from pathlib import Path

from patchtriage.dedup import dedup
from patchtriage.ingest.parsers import load_file
from patchtriage.models import Enrichment
from patchtriage.triage.engine import CascadeBackend, RulesBackend, run_triage

FIX = Path(__file__).parent / "fixtures"


class FakeBackend:
    def __init__(self, result: dict, fail: bool = False):
        self.result = result
        self.fail = fail
        self.calls = 0

    def triage(self, f):
        self.calls += 1
        if self.fail:
            raise RuntimeError("simulated API failure")
        return dict(self.result)


def _findings():
    raw = load_file(FIX / "trivy_sample.json") + load_file(FIX / "grype_sample.json")
    return dedup(raw)


def _kev_finding():
    f = next(x for x in _findings() if "libc" in x.package.name)
    f.asset.internet_exposed = True
    f.asset.criticality = "critical"
    f.enrichment = Enrichment(in_cisa_kev=True, kev_ransomware=True,
                              epss_score=0.856, nvd_cvss_score=7.8)
    return f


def _quiet_finding():
    f = next(x for x in _findings() if x.package.name == "lodash")
    f.asset.internet_exposed = False
    f.asset.criticality = "low"
    f.enrichment = Enrichment(epss_score=0.018, nvd_cvss_score=7.2)
    return f


def test_cascade_escalates_kev_to_deep_model():
    screen = FakeBackend({"priority": "P1", "action": "patch_now",
                          "rationale": "kev", "suggested_deadline_days": 3})
    deep = FakeBackend({"priority": "P1", "action": "patch_now",
                        "rationale": "actively exploited",
                        "suggested_deadline_days": 3})
    cascade = CascadeBackend(screen=screen, deep=deep)
    out = cascade.triage(_kev_finding())
    assert deep.calls == 1
    assert out["escalated"] is True
    assert "kev" in out["escalation_reasons"]
    assert out["rationale"] == "actively exploited"


def test_cascade_keeps_clean_low_signal_finding_on_screen_tier():
    # Matches the rules baseline (P3 for CVSS 7.2 / EPSS 0.018) and passes
    # every audit check -> no reason to spend frontier tokens.
    screen = FakeBackend({"priority": "P3", "action": "patch_scheduled",
                          "rationale": "low exploitation probability, fix exists",
                          "suggested_deadline_days": 30})
    deep = FakeBackend({"priority": "P1", "action": "patch_now",
                        "rationale": "should not be called",
                        "suggested_deadline_days": 1})
    cascade = CascadeBackend(screen=screen, deep=deep)
    out = cascade.triage(_quiet_finding())
    assert deep.calls == 0
    assert out["escalated"] is False


def test_cascade_escalates_on_audit_flag():
    # Screening decision downgrades despite matching no high-signal criteria?
    # Use a fabricated number in the rationale to trip the audit.
    screen = FakeBackend({"priority": "P3", "action": "patch_scheduled",
                          "rationale": "EPSS of 0.99 is unlikely",
                          "suggested_deadline_days": 30})
    deep = FakeBackend({"priority": "P3", "action": "patch_scheduled",
                        "rationale": "corrected", "suggested_deadline_days": 30})
    cascade = CascadeBackend(screen=screen, deep=deep)
    out = cascade.triage(_quiet_finding())
    assert deep.calls == 1
    assert any(r.startswith("audit_flags:") for r in out["escalation_reasons"])


def test_run_triage_falls_back_to_rules_on_api_error():
    findings = _findings()
    failing = FakeBackend({}, fail=True)
    run_triage(findings, failing, jobs=1)
    assert all(f.triage["backend"] == "rules_fallback" for f in findings)
    assert all("simulated API failure" in f.triage["error"] for f in findings)
    # fallback decisions are still real rules decisions
    assert all(f.triage["priority"] in ("P1", "P2", "P3", "P4") for f in findings)


def test_run_triage_parallel_preserves_order():
    findings = _findings()
    ok = FakeBackend({"priority": "P2", "action": "patch_scheduled",
                      "rationale": "x", "suggested_deadline_days": 14})
    run_triage(findings, ok, jobs=4)
    assert ok.calls == len(findings)
    assert all(f.triage["priority"] == "P2" for f in findings)


def test_rules_backend_errors_are_not_masked():
    # RulesBackend has no fallback path — a bug should surface loudly.
    findings = _findings()
    rules = RulesBackend()
    run_triage(findings, rules)
    assert all(f.triage["backend"] == "rules" for f in findings)
