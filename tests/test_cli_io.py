"""CLI input admission and output writes must preserve selected evidence."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from vcp_supervision import cli
from vcp_supervision.models import VerificationResult, VerificationStatus


ROOT = Path(__file__).resolve().parents[1]
SAVED_RESULT = {
    "status": "PASSED", "score": 1,
    **dict.fromkeys(cli._COMPONENT_FIELDS, True),
}


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "vcp_supervision.cli", *map(str, args)],
        cwd=ROOT, env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        capture_output=True, text=True, timeout=20,
    )


def bundle(event, proof, anchor):
    return {"event": event.model_dump(mode="json"),
            "proof": proof.model_dump(mode="json"),
            "anchor": anchor.model_dump(mode="json")}


@pytest.mark.parametrize("command", ["verify", "report"])
@pytest.mark.parametrize("invalid", [
    b'{"status":"FAILED","status":"PASSED"}',
    b'{"ignored":{"value":1,"value":2}}',
    b'{"ignored":NaN}', b'{"ignored":Infinity}', b'{"ignored":-Infinity}',
    b'{"ignored":1e999}', b'{"ignored":"\xff"}', b'{',
])
def test_ambiguous_or_invalid_json_does_not_create_a_report(tmp_path, command, invalid):
    source, output = tmp_path / "source.json", tmp_path / "output.json"
    source.write_bytes(invalid if command == "verify" else b'[' + invalid + b']')
    before = source.read_bytes()
    result = run_cli(command, source, "--output", output)
    assert result.returncode == 2, result.stdout + result.stderr
    assert "Command failed" in result.stderr
    assert "Traceback" not in result.stderr
    assert not output.exists()
    assert source.read_bytes() == before


def test_duplicate_status_cannot_hide_a_failed_saved_result(tmp_path):
    source = tmp_path / "results.json"
    raw = json.dumps([SAVED_RESULT]).replace('"status": "PASSED"',
        '"status": "FAILED", "status": "PASSED"')
    source.write_text(raw)
    result = run_cli("report", source)
    assert result.returncode == 2
    assert '"passed_events"' not in result.stdout
    assert source.read_text() == raw


@pytest.mark.parametrize("command", ["verify", "report"])
@pytest.mark.parametrize("alias", ["same", "symlink", "hardlink", "config", "unrelated"])
def test_existing_output_paths_cannot_overwrite_inputs_or_other_files(
    tmp_path, command, alias, sample_vcp_event, sample_merkle_proof, sample_anchor,
):
    source, config = tmp_path / "source.json", tmp_path / "config.yaml"
    data = ([SAVED_RESULT] if command == "report" else
            bundle(sample_vcp_event, sample_merkle_proof, sample_anchor))
    source.write_text(json.dumps(data))
    config.write_text("{}\n")
    output = tmp_path / "output.json"
    if alias == "same":
        output = source
    elif alias == "symlink":
        output.symlink_to(source)
    elif alias == "hardlink":
        os.link(source, output)
    elif alias == "config":
        output = config
    else:
        output.write_bytes(b"existing unrelated output\n")
    before = {path: path.read_bytes() for path in (source, config, output)}
    result = run_cli("--config", config, command, source, "--output", output)
    assert result.returncode == 2, result.stdout + result.stderr
    assert "Traceback" not in result.stderr
    assert "written to" not in result.stdout
    for path, raw in before.items():
        assert path.read_bytes() == raw


@pytest.mark.parametrize("status, expected", [
    ("PASSED", 2), ("FAILED", 1), ("INDETERMINATE", 2),
])
def test_export_failure_is_not_success_and_keeps_known_failure(
    tmp_path, monkeypatch, sample_vcp_event, sample_merkle_proof, sample_anchor,
    status, expected,
):
    class SyntheticNode:
        closed = False

        def __init__(self, **_kwargs):
            pass

        def verify_event(self, **_kwargs):
            return VerificationResult(status=VerificationStatus(status))

        def close(self):
            SyntheticNode.closed = True

    monkeypatch.setattr(cli, "SupervisionNode", SyntheticNode)
    source, output = tmp_path / "events.json", tmp_path / "output.json"
    source.write_text(json.dumps(bundle(sample_vcp_event, sample_merkle_proof, sample_anchor)))
    output.write_bytes(b"already present\n")
    args = cli.create_parser().parse_args(["verify", str(source), "--output", str(output)])
    assert cli.cmd_verify(args) == expected
    assert SyntheticNode.closed
    assert output.read_bytes() == b"already present\n"


def test_finite_exponent_metadata_is_accepted(tmp_path):
    source = tmp_path / "results.json"
    source.write_text(json.dumps([SAVED_RESULT]).replace('"score": 1',
                      '"score": 1, "details": {"finite_metadata": 1e2}'))
    result = run_cli("report", source)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["passed_events"] == 1


def test_serialization_error_does_not_create_a_partial_output(tmp_path):
    output = tmp_path / "output.json"
    with pytest.raises(ValueError):
        cli._write_new_json(str(output), {"invalid": float("nan")})
    assert not output.exists()
