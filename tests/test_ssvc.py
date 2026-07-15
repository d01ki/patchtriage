"""Conformance and inference tests for the SSVC Deployer implementation."""

from datetime import datetime, timezone
from itertools import product
from pathlib import Path

import pytest

from patchtriage.dedup import dedup
from patchtriage.ingest.parsers import load_file
from patchtriage.models import Asset, Enrichment
from patchtriage.ssvc import (
    Automatable,
    DeployerDecision,
    Exploitation,
    HumanImpact,
    MissionImpact,
    SafetyImpact,
    SystemExposure,
    assess,
    deployer_decision,
    derive_human_impact,
)

FIX = Path(__file__).parent / "fixtures" / "trivy_sample.json"


def _finding():
    finding = dedup(load_file(FIX))[0]
    finding.asset = Asset(identifier="checkout")
    finding.package.fixed_version = finding.package.fixed_version or "fixed"
    finding.enrichment = Enrichment(enriched_at=datetime.now(timezone.utc))
    return finding


def _explicit_context(finding, *, exposure="open", automatable="yes",
                      mission="mef_failure", safety="marginal"):
    finding.asset.system_exposure = exposure
    finding.asset.automatable = automatable
    finding.asset.mission_impact = mission
    finding.asset.safety_impact = safety
    return finding


def test_deployer_table_covers_all_72_paths():
    outcomes = []
    for values in product(
        Exploitation, SystemExposure, Automatable, HumanImpact
    ):
        outcomes.append(deployer_decision(*values))
    assert len(outcomes) == 72
    assert set(outcomes) == set(DeployerDecision)


def test_deployer_table_matches_all_official_rows():
    # Each four-letter group is Low/Medium/High/Very High; groups are
    # Small-No, Small-Yes, Controlled-No, Controlled-Yes, Open-No, Open-Yes.
    expected = {
        Exploitation.NONE: (
            "DDSS", "DSSS", "DSSS", "SSSS", "DSSS", "SSSO",
        ),
        Exploitation.PUBLIC_POC: (
            "DSSS", "SSSS", "DSSS", "SSSO", "SSSO", "SSOO",
        ),
        Exploitation.ACTIVE: (
            "SSOO", "SOOO", "SSOO", "OOOO", "SOOI", "OOII",
        ),
    }
    outcome_letter = {
        DeployerDecision.DEFER: "D",
        DeployerDecision.SCHEDULED: "S",
        DeployerDecision.OUT_OF_CYCLE: "O",
        DeployerDecision.IMMEDIATE: "I",
    }
    for exploitation, groups in expected.items():
        index = 0
        for exposure in SystemExposure:
            for automatable in Automatable:
                actual = "".join(
                    outcome_letter[deployer_decision(
                        exploitation, exposure, automatable, impact
                    )]
                    for impact in HumanImpact
                )
                assert actual == groups[index]
                index += 1


def test_asset_rejects_invalid_ssvc_context():
    with pytest.raises(ValueError, match="system_exposure"):
        Asset(identifier="x", system_exposure="sort-of-open")
    assert Asset(identifier="x", automatable=True).automatable == "yes"


def test_key_official_deployer_paths():
    assert deployer_decision(
        Exploitation.ACTIVE, SystemExposure.OPEN,
        Automatable.YES, HumanImpact.HIGH,
    ) == DeployerDecision.IMMEDIATE
    assert deployer_decision(
        Exploitation.ACTIVE, SystemExposure.SMALL,
        Automatable.NO, HumanImpact.LOW,
    ) == DeployerDecision.SCHEDULED
    assert deployer_decision(
        Exploitation.NONE, SystemExposure.OPEN,
        Automatable.YES, HumanImpact.VERY_HIGH,
    ) == DeployerDecision.OUT_OF_CYCLE
    assert deployer_decision(
        Exploitation.NONE, SystemExposure.SMALL,
        Automatable.NO, HumanImpact.LOW,
    ) == DeployerDecision.DEFER


def test_human_impact_combination_table_boundaries():
    assert derive_human_impact(
        MissionImpact.DEGRADED, SafetyImpact.NEGLIGIBLE
    ) == HumanImpact.LOW
    assert derive_human_impact(
        MissionImpact.DEGRADED, SafetyImpact.MARGINAL
    ) == HumanImpact.LOW
    assert derive_human_impact(
        MissionImpact.MEF_FAILURE, SafetyImpact.MARGINAL
    ) == HumanImpact.MEDIUM
    assert derive_human_impact(
        MissionImpact.MEF_SUPPORT_CRIPPLED, SafetyImpact.CRITICAL
    ) == HumanImpact.HIGH
    assert derive_human_impact(
        MissionImpact.MISSION_FAILURE, SafetyImpact.NEGLIGIBLE
    ) == HumanImpact.VERY_HIGH


def test_human_impact_table_covers_all_16_official_rows():
    # Rows are ordered by Mission Impact: Degraded, Support Crippled,
    # MEF Failure, Mission Failure.
    expected = {
        SafetyImpact.NEGLIGIBLE: (
            HumanImpact.LOW, HumanImpact.LOW,
            HumanImpact.MEDIUM, HumanImpact.VERY_HIGH,
        ),
        SafetyImpact.MARGINAL: (
            HumanImpact.LOW, HumanImpact.LOW,
            HumanImpact.MEDIUM, HumanImpact.VERY_HIGH,
        ),
        SafetyImpact.CRITICAL: (
            HumanImpact.MEDIUM, HumanImpact.HIGH,
            HumanImpact.HIGH, HumanImpact.VERY_HIGH,
        ),
        SafetyImpact.CATASTROPHIC: (HumanImpact.VERY_HIGH,) * 4,
    }
    for safety, outcomes in expected.items():
        for mission, outcome in zip(MissionImpact, outcomes):
            assert derive_human_impact(mission, safety) == outcome


def test_kev_sets_active_but_does_not_bypass_environment_context():
    finding = _explicit_context(
        _finding(), exposure="small", automatable="no",
        mission="degraded", safety="negligible",
    )
    finding.enrichment.in_cisa_kev = True
    result = assess(finding)
    assert result.exploitation.value == "active"
    assert result.decision == DeployerDecision.SCHEDULED
    assert result.priority == "P3"


def test_epss_is_supplemental_not_observed_exploitation():
    finding = _explicit_context(_finding())
    finding.enrichment.epss_score = 0.99
    result = assess(finding)
    assert result.exploitation.value == "none"
    assert result.supplemental["epss"] == 0.99


def test_public_exploit_reference_sets_public_poc():
    finding = _explicit_context(_finding())
    finding.enrichment.exploit_references = ["https://example.test/poc"]
    assert assess(finding).exploitation.value == "public_poc"


def test_explicit_context_is_high_confidence_and_needs_no_confirmation():
    finding = _explicit_context(_finding())
    result = assess(finding)
    assert result.needs_confirmation == []
    # Absence of observed exploitation is evidence-backed, but remains medium
    # confidence; all organization-owned context inputs are high confidence.
    assert result.confidence.value == "medium"
    assert result.system_exposure.confidence.value == "high"
    assert result.mission_impact.confidence.value == "high"
    assert result.priority == "P3"


def test_unknown_context_uses_visible_conservative_defaults():
    finding = _finding()
    finding.enrichment = Enrichment()
    result = assess(finding)
    assert result.system_exposure.value == "open"
    assert result.automatable.value == "yes"
    assert result.mission_impact.value == "mef_support_crippled"
    assert result.safety_impact.value == "marginal"
    assert set(result.needs_confirmation) == {
        "exploitation", "system_exposure", "automatable",
        "mission_impact", "safety_impact",
    }


def test_no_fix_changes_remediation_not_ssvc_priority():
    finding = _explicit_context(_finding(), safety="critical")
    finding.enrichment.in_cisa_kev = True
    finding.package.fixed_version = ""
    result = assess(finding)
    assert result.priority == "P1"
    assert result.recommended_action == "mitigate"
