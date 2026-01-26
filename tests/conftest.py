"""
Pytest configuration and shared fixtures.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vcp_supervision.models import (
    AnchorRecord,
    AnchorType,
    AuthorizedKey,
    ClockSyncStatus,
    MerkleProof,
    PublicKeyManifest,
    TimestampPrecision,
    TSAAnchor,
    VCPEvent,
    VCPSignature,
)


@pytest.fixture
def ed25519_keypair():
    """Generate an Ed25519 key pair for testing."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    public_key_bytes = public_key.public_bytes_raw()
    public_key_b64 = base64.b64encode(public_key_bytes).decode()
    
    return private_key, public_key_b64


@pytest.fixture
def public_key_manifest(ed25519_keypair):
    """Create a test public key manifest."""
    _, public_key_b64 = ed25519_keypair
    
    key_bytes = base64.b64decode(public_key_b64)
    fingerprint = hashlib.sha256(key_bytes).hexdigest()
    
    return PublicKeyManifest(
        manifest_id="test-manifest-001",
        version=1,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        authorized_keys={
            fingerprint: AuthorizedKey(
                fingerprint=fingerprint,
                public_key=public_key_b64,
                algorithm="Ed25519",
                entity_name="Test Entity",
                entity_id="TEST-001",
                valid_from=datetime(2024, 1, 1, tzinfo=timezone.utc),
                valid_until=None,
                revoked=False,
            )
        },
    )


@pytest.fixture
def sample_vcp_event(ed25519_keypair):
    """Create a sample VCP event with valid signature."""
    private_key, public_key_b64 = ed25519_keypair
    
    event_data = {
        "event_id": "01234567-89ab-cdef-0123-456789abcdef",
        "timestamp": datetime.now(timezone.utc),
        "timestamp_precision": TimestampPrecision.MILLISECOND,
        "clock_sync_status": ClockSyncStatus.NTP_SYNCED,
        "sequence_num": 1,
        "prev_hash": "0" * 64,
        "event_type": "ORDER_NEW",
        "payload": {"symbol": "EURUSD", "quantity": 1000},
    }
    
    # Canonicalize for signing
    signed_fields = {
        "event_id": event_data["event_id"],
        "timestamp": event_data["timestamp"].isoformat(),
        "timestamp_precision": event_data["timestamp_precision"].value,
        "clock_sync_status": event_data["clock_sync_status"].value,
        "sequence_num": event_data["sequence_num"],
        "prev_hash": event_data["prev_hash"],
        "event_type": event_data["event_type"],
        "payload": event_data["payload"],
    }
    canonical = json.dumps(signed_fields, sort_keys=True, separators=(",", ":"))
    
    # Sign the event
    signature = private_key.sign(canonical.encode())
    signature_b64 = base64.b64encode(signature).decode()
    
    return VCPEvent(
        **event_data,
        signature=VCPSignature(
            algorithm="Ed25519",
            public_key=public_key_b64,
            value=signature_b64,
        ),
    )


@pytest.fixture
def sample_merkle_proof(sample_vcp_event):
    """Create a sample Merkle proof for a single-leaf tree."""
    # Compute the leaf hash
    event_dict = {
        "event_id": sample_vcp_event.event_id,
        "timestamp": sample_vcp_event.timestamp.isoformat(),
        "timestamp_precision": sample_vcp_event.timestamp_precision.value,
        "clock_sync_status": sample_vcp_event.clock_sync_status.value,
        "sequence_num": sample_vcp_event.sequence_num,
        "prev_hash": sample_vcp_event.prev_hash,
        "event_type": sample_vcp_event.event_type,
        "payload": sample_vcp_event.payload,
        "signature": {
            "algorithm": sample_vcp_event.signature.algorithm,
            "public_key": sample_vcp_event.signature.public_key,
            "value": sample_vcp_event.signature.value,
        },
    }
    event_bytes = json.dumps(event_dict, sort_keys=True, separators=(",", ":")).encode()
    leaf_hash = hashlib.sha256(b"\x00" + event_bytes).digest()
    
    return MerkleProof(
        leaf_index=0,
        tree_size=1,
        root_hash=base64.b64encode(leaf_hash).decode(),
        path=[],
        directions=[],
    )


@pytest.fixture
def sample_anchor(sample_merkle_proof):
    """Create a sample anchor record."""
    return AnchorRecord(
        anchor_type=AnchorType.TSA,
        merkle_root=sample_merkle_proof.root_hash,
        anchor_timestamp=datetime.now(timezone.utc),
        batch_start_seq=0,
        batch_end_seq=1,
        tsa_anchor=TSAAnchor(
            tsa_url="https://freetsa.org/tsr",
            token=base64.b64encode(b"mock-tsp-token").decode(),
            timestamp=datetime.now(timezone.utc),
            is_eidas_qualified=False,
        ),
    )


@pytest.fixture
def supervision_node():
    """Create a SupervisionNode for testing."""
    from vcp_supervision import SupervisionNode
    
    node = SupervisionNode(
        config={
            "verification": {
                "signature": {"require_manifest": False},
                "timing": {"default_jurisdiction": "EU"},
            }
        }
    )
    yield node
    node.close()


def pytest_configure(config):
    """Configure custom markers."""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "slow: Slow tests")
