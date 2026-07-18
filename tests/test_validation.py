import json

from typer.testing import CliRunner

from patchtriage.cli import app
from patchtriage.validation import run_validation


def test_reviewer_validation_passes_offline():
    report = run_validation(repeats=3)
    assert report["status"] == "pass"
    assert report["offline"] is True
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["official_ssvc_deployer_table"]["cases"] == 72
    assert checks["official_ssvc_human_impact_table"]["cases"] == 16
    assert checks["target_context_mapping_sensitivity"]["passed"] is True
    outcomes = {
        row["actual_decision"]
        for row in checks["target_context_mapping_sensitivity"]["observations"]
    }
    assert outcomes == {"immediate", "out_of_cycle", "scheduled"}
    assert checks["decision_tamper_detection"]["passed"] is True
    assert len(report["input_fingerprint"]) == 64
    assert len(report["decision_fingerprint"]) == 64


def test_reviewer_validation_is_repeatable_for_same_inputs():
    first = run_validation(repeats=3)
    second = run_validation(repeats=4)
    assert first["input_fingerprint"] == second["input_fingerprint"]
    assert first["decision_fingerprint"] == second["decision_fingerprint"]


def test_verify_command_writes_evidence(tmp_path):
    output = tmp_path / "evidence.json"
    result = CliRunner().invoke(
        app, ["verify", "--repeats", "3", "--output", str(output)],
    )
    assert result.exit_code == 0, result.output
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["status"] == "pass"
    assert "Decision fingerprint" in result.output
