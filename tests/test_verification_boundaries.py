"""Trust boundaries must remain enforced at the public API and engine entry points."""

import base64
import hashlib
from datetime import timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from vcp_supervision.api.auth import APIKeyAuth, JWTAuth, MTLSAuth
from vcp_supervision.api.server import create_app
from vcp_supervision.models import (
    AnchorType,
    BlockchainAnchor,
    MerkleProof,
    VerificationResult,
    VerificationStatus,
)
from vcp_supervision.verification.anchor import AnchorVerifier
from vcp_supervision.verification.engine import VerificationEngine
from vcp_supervision.verification.merkle import MerkleVerifier
from vcp_supervision.verification.signature import SignatureVerifier


def test_required_manifest_cannot_be_absent(sample_vcp_event):
    result = SignatureVerifier().verify(sample_vcp_event)
    assert result["status"] == "FAILED"
    assert result["error_code"] == "MANIFEST_REQUIRED"


@pytest.mark.parametrize("mutation", ["algorithm", "revoked", "future", "expired", "key"])
def test_manifest_does_not_authorize_mismatched_or_inactive_keys(
    sample_vcp_event, public_key_manifest, mutation
):
    entry = next(iter(public_key_manifest.authorized_keys.values()))
    if mutation == "algorithm":
        sample_vcp_event.signature.algorithm = "unsupported"
    elif mutation == "revoked":
        entry.revoked = True
    elif mutation == "future":
        entry.valid_from = sample_vcp_event.timestamp + timedelta(seconds=1)
    elif mutation == "expired":
        entry.valid_until = sample_vcp_event.timestamp
    else:
        entry.public_key = base64.b64encode(b"x" * 32).decode()
    assert SignatureVerifier(public_key_manifest).verify(sample_vcp_event)["status"] == "FAILED"


def test_valid_authorized_signature_still_passes(sample_vcp_event, public_key_manifest):
    assert SignatureVerifier(public_key_manifest).verify(sample_vcp_event)["status"] == "PASSED"


@pytest.mark.parametrize("online", [False, True])
def test_self_reported_blockchain_commitment_never_passes(sample_anchor, online):
    anchor = sample_anchor.model_copy(deep=True)
    anchor.anchor_type = AnchorType.BLOCKCHAIN
    anchor.tsa_anchor = None
    anchor.blockchain_anchor = BlockchainAnchor(
        chain="ethereum", network="mainnet", transaction_hash="0x" + "a" * 64,
        block_number=1, block_timestamp=anchor.anchor_timestamp,
        merkle_root_in_tx=anchor.merkle_root, confirmations=100000,
    )
    verifier = AnchorVerifier(
        verify_blockchain=online,
        blockchain_rpc_urls={"ethereum": "https://rpc.example.invalid"},
    )
    verifier._http_client.close()
    verifier._http_client = httpx.Client(transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json={"result": {"input": "0x"}})
    ))
    try:
        result = verifier.verify(anchor.merkle_root, anchor)
        direct = verifier._verify_blockchain_online(anchor.blockchain_anchor)
    finally:
        verifier.close()
    assert result["status"] == "FAILED"
    assert result["has_legal_presumption"] is False
    assert direct["status"] != "PASSED"


def test_proof_must_be_for_the_anchor_root(
    sample_vcp_event, sample_merkle_proof, sample_anchor, public_key_manifest
):
    sample_anchor.merkle_root = base64.b64encode(b"x" * 32).decode()
    with VerificationEngine(manifest=public_key_manifest) as engine:
        result = engine.verify_event(sample_vcp_event, sample_merkle_proof, sample_anchor)
    assert result.merkle_valid is False
    assert result.details["merkle"]["error_code"] == "MERKLE_ROOT_MISMATCH"


def test_single_leaf_cannot_claim_a_larger_tree(sample_vcp_event, sample_merkle_proof):
    sample_merkle_proof.tree_size = 2
    assert MerkleVerifier().verify(sample_vcp_event, sample_merkle_proof)["status"] == "FAILED"


def test_valid_odd_tree_path_and_index_binding(sample_vcp_event):
    verifier = MerkleVerifier()
    leaf = verifier._compute_leaf_hash(sample_vcp_event)
    left_subtree = hashlib.sha256(b"independent left subtree").digest()
    root = hashlib.sha256(b"\x01" + left_subtree + leaf).digest()
    proof = MerkleProof(
        leaf_index=2, tree_size=3, root_hash=base64.b64encode(root).decode(),
        path=[base64.b64encode(left_subtree).decode()], directions=["LEFT"],
    )
    assert verifier.verify(sample_vcp_event, proof)["status"] == "PASSED"
    proof.leaf_index = 0
    assert verifier.verify(sample_vcp_event, proof)["status"] == "FAILED"


@pytest.mark.parametrize("component_status", ["WARNING", "TIMEOUT", "UNKNOWN"])
def test_incomplete_checks_are_not_success(sample_vcp_event, component_status):
    results = {name: {"status": "PASSED"} for name in ("signature", "merkle", "anchor", "timing")}
    results["anchor"] = {"status": component_status}
    with VerificationEngine() as engine:
        result = engine._aggregate_results(
            sample_vcp_event, results, "EU", sample_vcp_event.timestamp,
            sample_vcp_event.timestamp, 0.0,
        )
    assert result.status != VerificationStatus.PASSED
    assert result.anchor_valid is False
    assert result.is_compliant is False


@pytest.mark.parametrize("failure", ["gap", "ordering", "extra"])
def test_batch_failures_propagate_to_results(sample_vcp_event, sample_anchor, monkeypatch, failure):
    events = [sample_vcp_event.model_copy(deep=True), sample_vcp_event.model_copy(deep=True)]
    events[0].sequence_num = 1
    events[1].sequence_num = 3 if failure == "gap" else 2
    events[1].timestamp += timedelta(seconds=-1 if failure == "ordering" else 1)
    sample_anchor.batch_start_seq = 1
    sample_anchor.batch_end_seq = 1 if failure == "extra" else 2
    with VerificationEngine() as engine:
        # Isolate aggregate behavior from the deliberately unimplemented anchor check.
        monkeypatch.setattr(engine, "verify_event", lambda **kwargs: VerificationResult(
            status=VerificationStatus.PASSED, compliance_score=1.0,
        ))
        results = engine.verify_batch(events, [None, None], sample_anchor)
    assert all(result.status == VerificationStatus.FAILED for result in results)
    assert all(not result.is_compliant and result.compliance_score == 0 for result in results)


@pytest.mark.parametrize("path", ["/verify/event", "/challenge/create", "/reports/compliance", "/admin/config"])
def test_default_app_denies_protected_routes(path):
    with TestClient(create_app()) as client:
        method = client.get if path.startswith("/admin/") else client.post
        response = method(path)
        assert response.status_code == 401
        assert client.get("/health").status_code == 200


@pytest.mark.parametrize("scheme,headers", [
    (JWTAuth(), {"Authorization": "Bearer arbitrary"}),
    (MTLSAuth(), {"X-Client-Cert-DN": "CN=arbitrary"}),
])
def test_placeholder_auth_rejected_through_real_app(scheme, headers):
    with TestClient(create_app(auth_scheme=scheme)) as client:
        assert client.get("/admin/config", headers=headers).status_code == 501


def test_api_key_permissions_enforced_before_route_handler():
    auth = APIKeyAuth(valid_keys={
        "reader": {"permissions": ["read"]},
        "writer": {"permissions": ["write"]},
        "admin": {"permissions": ["admin"]},
    })
    with TestClient(create_app(auth_scheme=auth)) as client:
        assert client.get("/admin/config", headers={"X-API-Key": "reader"}).status_code == 403
        assert client.post("/verify/event", headers={"X-API-Key": "reader"}).status_code == 403
        assert client.get("/admin/config", headers={"X-API-Key": "writer"}).status_code == 403
        # Correct credentials reach the handler, which has no node configured here.
        assert client.get("/admin/config", headers={"X-API-Key": "admin"}).status_code == 503


def test_dashboard_also_denies_unconfigured_access():
    from vcp_supervision.dashboard.app import ComplianceDashboard

    dashboard = ComplianceDashboard()
    with TestClient(dashboard.app) as client:
        assert client.get("/api/results").status_code == 401
        assert client.post("/api/results", json={"status": "PASSED"}).status_code == 401
    assert dashboard._results == []
