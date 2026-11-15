"""CLI outcomes and saved reports must preserve incomplete verification."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from vcp_supervision import cli
from vcp_supervision.models import VerificationResult, VerificationStatus


ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args):
    environment = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    return subprocess.run(
        [sys.executable, "-m", "vcp_supervision.cli", *map(str, args)],
        cwd=ROOT, env=environment, capture_output=True, text=True, timeout=20,
    )


def event_bundle(event, proof, anchor):
    return {"event": event.model_dump(mode="json"),
            "proof": proof.model_dump(mode="json"),
            "anchor": anchor.model_dump(mode="json")}


def test_real_cli_round_trip_keeps_missing_trust_unverified(
    tmp_path, sample_vcp_event, sample_merkle_proof, sample_anchor
):
    events, saved = tmp_path / "events.json", tmp_path / "results.json"
    events.write_text(json.dumps(event_bundle(sample_vcp_event, sample_merkle_proof, sample_anchor)))
    verified = run_cli("verify", events, "--output", saved)
    assert verified.returncode == 2, verified.stdout + verified.stderr
    assert "Unverified: 1" in verified.stdout
    record = json.loads(saved.read_text())[0]
    assert record["status"] == "INDETERMINATE"
    assert record["signature_valid"] is False
    assert record["anchor_valid"] is False
    assert record["merkle_valid"] is True
    assert record["details"]["signature"]["error_code"] == "MANIFEST_REQUIRED"
    assert record["message"]
    assert record["score"] == record["compliance_score"]
    assert record["verification_started_at"]
    assert record["verification_completed_at"]

    reported = run_cli("report", saved)
    assert reported.returncode == 0, reported.stdout + reported.stderr
    # Diagnostic JSON records must not contaminate the report JSON on stdout.
    report = json.loads(reported.stdout)
    assert report["passed_events"] == 0
    assert report["indeterminate_events"] == 1
    assert report["integrity_score"] == 0
    assert record["message"] in "\n".join(report["issues"])


@pytest.mark.parametrize("statuses, expected", [
    ([], 2),
    (["PASSED"], 0),
    (["INDETERMINATE"], 2),
    (["WARNING"], 2),
    (["TIMEOUT"], 2),
    (["PASSED", "INDETERMINATE"], 2),
    (["FAILED", "INDETERMINATE"], 1),
    (["FAILED", "PASSED"], 1),
])
def test_verify_exit_codes_cover_all_terminal_states(
    tmp_path, monkeypatch, sample_vcp_event, sample_merkle_proof, sample_anchor,
    statuses, expected,
):
    # Synthetic engine results isolate CLI exit handling; the real crypto path
    # and serialization are exercised by the subprocess round-trip above.
    remaining = iter(statuses)

    class SyntheticNode:
        closed = False

        def __init__(self, **_kwargs):
            pass

        def verify_event(self, **_kwargs):
            status = next(remaining)
            return VerificationResult(status=VerificationStatus(status))

        def close(self):
            SyntheticNode.closed = True

    monkeypatch.setattr(cli, "SupervisionNode", SyntheticNode)
    events = tmp_path / "events.json"
    bundle = event_bundle(sample_vcp_event, sample_merkle_proof, sample_anchor)
    events.write_text(json.dumps([bundle] * len(statuses)))
    args = cli.create_parser().parse_args(["--verbose", "verify", str(events)])
    assert cli.cmd_verify(args) == expected
    assert SyntheticNode.closed


@pytest.mark.parametrize("record, status_field", [
    ({"status": "INDETERMINATE", "score": 0.5}, "indeterminate_events"),
    ({"status": "PASSED", "score": 1}, "indeterminate_events"),
    ({"status": "PASSED", "score": 1, "signature_valid": False,
      "merkle_valid": True, "anchor_valid": True, "timing_valid": True}, "failed_events"),
])
def test_saved_results_cannot_invent_success_for_absent_or_failed_checks(tmp_path, record, status_field):
    saved = tmp_path / "legacy.json"
    saved.write_text(json.dumps([record]))
    process = run_cli("report", saved)
    assert process.returncode == 0, process.stdout + process.stderr
    report = json.loads(process.stdout)
    assert report["passed_events"] == 0
    assert report[status_field] == 1
    assert report["integrity_score"] == 0
    if "timing_valid" not in record:
        assert report["timing_score"] == 0


def test_reload_preserves_explicit_null_false_and_diagnostics():
    original = VerificationResult(
        status=VerificationStatus.INDETERMINATE, compliance_score=0.25,
        signature_valid=None, merkle_valid=True, anchor_valid=False, timing_valid=None,
        error_code="TEST_UNAVAILABLE", message="Synthetic source is unavailable",
        warnings=["Synthetic warning"], details={"signature": {"status": "INDETERMINATE"}},
    )
    restored = cli._restore_result(json.loads(original.model_dump_json()))
    assert restored.model_dump() == original.model_dump()


@pytest.mark.parametrize("value", ["true", "false", 1, 0, [], {}])
def test_saved_component_values_are_not_coerced_into_success(value):
    with pytest.raises(ValueError, match="boolean or null"):
        cli._restore_result({"status": "PASSED", "signature_valid": value})


def test_complete_saved_positive_result_remains_a_local_positive_report(tmp_path):
    record = {"status": "PASSED", "score": 1,
              **dict.fromkeys(cli._COMPONENT_FIELDS, True)}
    saved, output = tmp_path / "saved.json", tmp_path / "report.json"
    saved.write_text(json.dumps([record]))
    process = run_cli("report", saved, "--output", output)
    assert process.returncode == 0, process.stdout + process.stderr
    report = json.loads(output.read_text())
    assert report["passed_events"] == 1
    assert report["integrity_score"] == 1
    assert report["timing_score"] == 1
