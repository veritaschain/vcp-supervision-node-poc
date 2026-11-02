"""Unverified evidence is visible as indeterminate, never accepted as success."""

import base64

import pytest
from fastapi.testclient import TestClient

from vcp_supervision import SupervisionNode
from vcp_supervision.api.auth import APIKeyAuth, JWTAuth, MTLSAuth, create_auth_scheme
from vcp_supervision.dashboard.app import ComplianceDashboard
from vcp_supervision.models import VerificationResult, VerificationStatus
from vcp_supervision.verification.engine import VerificationEngine
from vcp_supervision.verification.signature import SignatureVerifier


def test_bad_signature_is_a_failure_even_without_a_manifest(sample_vcp_event):
    sample_vcp_event.signature.value = base64.b64encode(b"x" * 64).decode()
    result = SignatureVerifier().verify(sample_vcp_event)
    assert result["status"] == "FAILED"
    assert result["error_code"] == "SIG_INVALID"


def test_unregistered_key_remains_indeterminate(sample_vcp_event, public_key_manifest):
    public_key_manifest.authorized_keys.clear()
    result = SignatureVerifier(public_key_manifest).verify(sample_vcp_event)
    assert result["status"] == "INDETERMINATE"
    assert result["error_code"] == "KEY_NOT_AUTHORIZED"


def test_missing_trust_round_trips_as_indeterminate(
    sample_vcp_event, sample_merkle_proof, sample_anchor
):
    with VerificationEngine() as engine:
        result = engine.verify_event(sample_vcp_event, sample_merkle_proof, sample_anchor)
    assert result.status == VerificationStatus.INDETERMINATE
    assert result.signature_valid is False
    assert result.anchor_valid is False
    assert result.is_compliant is False
    restored = VerificationResult.model_validate_json(result.model_dump_json())
    assert restored.status == VerificationStatus.INDETERMINATE
    assert restored.is_compliant is False


def test_observed_bad_signature_wins_over_missing_tsa_verification(
    sample_vcp_event, sample_merkle_proof, sample_anchor, public_key_manifest
):
    sample_vcp_event.signature.value = base64.b64encode(b"x" * 64).decode()
    with VerificationEngine(manifest=public_key_manifest) as engine:
        result = engine.verify_event(sample_vcp_event, sample_merkle_proof, sample_anchor)
    assert result.status == VerificationStatus.FAILED
    assert result.error_code == "SIG_INVALID"
    assert result.is_compliant is False


@pytest.mark.parametrize("method", ["jwt", "mtls"])
def test_unsupported_auth_factory_refuses_configuration(method):
    with pytest.raises(RuntimeError, match="server startup refused"):
        create_auth_scheme(method)


@pytest.mark.parametrize("scheme", [JWTAuth(), MTLSAuth()])
def test_dashboard_does_not_start_with_placeholder_auth(scheme):
    with pytest.raises(RuntimeError, match="server startup refused"):
        with TestClient(ComplianceDashboard(auth_scheme=scheme).app):
            pytest.fail("Unsupported authentication must prevent startup")


def test_indeterminate_is_counted_in_reports_and_dashboard():
    result = VerificationResult(
        status=VerificationStatus.INDETERMINATE,
        error_code="MANIFEST_REQUIRED", message="Missing trusted manifest",
        jurisdiction="EU", signature_valid=False, anchor_valid=False,
    )
    with SupervisionNode() as node:
        node._update_stats(result)
        stats = node.get_stats()
        assert stats["events_indeterminate"] == 1
        assert stats["events_passed"] == stats["events_failed"] == 0
        report = node.generate_compliance_report([result], "EU")
        assert report.indeterminate_events == 1
        assert report.passed_events == report.failed_events == 0
        assert report.pass_rate == 0
        assert "MANIFEST_REQUIRED" in report.issues[0]

    auth = APIKeyAuth({"synthetic-reader": {"permissions": ["read"]}})
    dashboard = ComplianceDashboard(auth_scheme=auth)
    dashboard._results.append(result.model_dump(mode="json"))
    with TestClient(dashboard.app) as client:
        headers = {"X-API-Key": "synthetic-reader"}
        response = client.get("/api/stats", headers=headers)
        assert response.status_code == 200
        stats = response.json()
        assert stats["events_indeterminate"] == 1
        assert stats["events_passed"] == stats["events_failed"] == 0
        assert stats["pass_rate"] == 0
        assert "Indeterminate" in client.get("/", headers=headers).text
