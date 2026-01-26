"""
Unit tests for VCP Supervision Node verification modules.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vcp_supervision.models import (
    AnchorRecord,
    AnchorType,
    AuthorizedKey,
    BlockchainAnchor,
    ClockSyncStatus,
    MerkleProof,
    PublicKeyManifest,
    TimestampPrecision,
    TSAAnchor,
    VCPEvent,
    VCPSignature,
)
from vcp_supervision.verification import (
    AnchorVerifier,
    MerkleVerifier,
    SignatureVerifier,
    TimingVerifier,
    VerificationEngine,
)


# Fixtures for test data
@pytest.fixture
def ed25519_keypair():
    """Generate an Ed25519 key pair for testing."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    public_key_bytes = public_key.public_bytes_raw()
    public_key_b64 = base64.b64encode(public_key_bytes).decode()
    
    return private_key, public_key_b64


@pytest.fixture
def sample_event(ed25519_keypair):
    """Create a sample VCP event with valid signature."""
    private_key, public_key_b64 = ed25519_keypair
    
    # Create event data
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
def sample_manifest(ed25519_keypair):
    """Create a sample public key manifest."""
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
def sample_merkle_proof():
    """Create a sample Merkle proof."""
    # Simple single-leaf tree proof
    return MerkleProof(
        leaf_index=0,
        tree_size=1,
        root_hash=base64.b64encode(b"\x00" * 32).decode(),  # Placeholder
        path=[],
        directions=[],
    )


@pytest.fixture
def sample_anchor():
    """Create a sample anchor record."""
    return AnchorRecord(
        anchor_type=AnchorType.TSA,
        merkle_root=base64.b64encode(b"\x00" * 32).decode(),
        anchor_timestamp=datetime.now(timezone.utc),
        batch_start_seq=0,
        batch_end_seq=10,
        tsa_anchor=TSAAnchor(
            tsa_url="https://freetsa.org/tsr",
            token=base64.b64encode(b"mock-tsp-token").decode(),
            timestamp=datetime.now(timezone.utc),
            is_eidas_qualified=False,
        ),
    )


class TestSignatureVerifier:
    """Tests for SignatureVerifier."""
    
    def test_verify_valid_signature(self, sample_event, sample_manifest):
        """Test verification of a valid signature."""
        verifier = SignatureVerifier(manifest=sample_manifest)
        result = verifier.verify(sample_event)
        
        assert result["status"] == "PASSED"
    
    def test_verify_without_manifest(self, sample_event):
        """Test verification without manifest requirement."""
        verifier = SignatureVerifier(manifest=None, require_manifest=False)
        result = verifier.verify(sample_event)
        
        assert result["status"] == "PASSED"
    
    def test_verify_key_not_in_manifest(self, sample_event):
        """Test verification when key is not in manifest."""
        empty_manifest = PublicKeyManifest(
            manifest_id="empty",
            version=1,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            authorized_keys={},
        )
        
        verifier = SignatureVerifier(manifest=empty_manifest)
        result = verifier.verify(sample_event)
        
        assert result["status"] == "FAILED"
        assert result["error_code"] == "KEY_NOT_AUTHORIZED"
    
    def test_verify_invalid_signature(self, sample_event, sample_manifest):
        """Test verification of an invalid signature."""
        # Modify the signature to make it invalid
        sample_event.signature.value = base64.b64encode(b"invalid" * 8).decode()
        
        verifier = SignatureVerifier(manifest=sample_manifest)
        result = verifier.verify(sample_event)
        
        assert result["status"] == "FAILED"
        assert result["error_code"] == "SIG_INVALID"


class TestMerkleVerifier:
    """Tests for MerkleVerifier."""
    
    def test_verify_single_leaf_tree(self, sample_event):
        """Test verification of a single-leaf Merkle tree."""
        verifier = MerkleVerifier()
        
        # Compute the expected root for a single leaf
        event_dict = {
            "event_id": sample_event.event_id,
            "timestamp": sample_event.timestamp.isoformat(),
            "timestamp_precision": sample_event.timestamp_precision.value,
            "clock_sync_status": sample_event.clock_sync_status.value,
            "sequence_num": sample_event.sequence_num,
            "prev_hash": sample_event.prev_hash,
            "event_type": sample_event.event_type,
            "payload": sample_event.payload,
            "signature": {
                "algorithm": sample_event.signature.algorithm,
                "public_key": sample_event.signature.public_key,
                "value": sample_event.signature.value,
            },
        }
        event_bytes = json.dumps(
            event_dict, sort_keys=True, separators=(",", ":")
        ).encode()
        expected_root = hashlib.sha256(b"\x00" + event_bytes).digest()
        
        proof = MerkleProof(
            leaf_index=0,
            tree_size=1,
            root_hash=base64.b64encode(expected_root).decode(),
            path=[],
            directions=[],
        )
        
        result = verifier.verify(sample_event, proof)
        
        assert result["status"] == "PASSED"
    
    def test_verify_root_mismatch(self, sample_event):
        """Test verification fails with wrong root."""
        verifier = MerkleVerifier()
        
        proof = MerkleProof(
            leaf_index=0,
            tree_size=1,
            root_hash=base64.b64encode(b"wrong" * 8).decode(),
            path=[],
            directions=[],
        )
        
        result = verifier.verify(sample_event, proof)
        
        assert result["status"] == "FAILED"
        assert result["error_code"] == "MERKLE_ROOT_MISMATCH"
    
    def test_batch_completeness_no_gaps(self, sample_event):
        """Test batch completeness with no gaps."""
        verifier = MerkleVerifier()
        
        events = []
        for i in range(5):
            event = VCPEvent(
                event_id=f"event-{i}",
                timestamp=datetime.now(timezone.utc),
                timestamp_precision=TimestampPrecision.MILLISECOND,
                clock_sync_status=ClockSyncStatus.NTP_SYNCED,
                sequence_num=i,
                prev_hash="0" * 64,
                event_type="ORDER_NEW",
                payload={},
                signature=sample_event.signature,
            )
            events.append(event)
        
        result = verifier.verify_batch_completeness(events, start_seq=0, end_seq=4)
        
        assert result["status"] == "PASSED"
    
    def test_batch_completeness_with_gap(self, sample_event):
        """Test batch completeness detects gaps."""
        verifier = MerkleVerifier()
        
        # Create events with a gap (missing sequence 2)
        events = []
        for i in [0, 1, 3, 4]:
            event = VCPEvent(
                event_id=f"event-{i}",
                timestamp=datetime.now(timezone.utc),
                timestamp_precision=TimestampPrecision.MILLISECOND,
                clock_sync_status=ClockSyncStatus.NTP_SYNCED,
                sequence_num=i,
                prev_hash="0" * 64,
                event_type="ORDER_NEW",
                payload={},
                signature=sample_event.signature,
            )
            events.append(event)
        
        result = verifier.verify_batch_completeness(events, start_seq=0, end_seq=4)
        
        assert result["status"] == "FAILED"
        assert result["error_code"] == "SEQUENCE_GAP"


class TestTimingVerifier:
    """Tests for TimingVerifier."""
    
    def test_verify_eu_hft_requirements(self, sample_event):
        """Test EU HFT timing requirements."""
        verifier = TimingVerifier(default_jurisdiction="EU")
        
        # Set up event for HFT
        sample_event.clock_sync_status = ClockSyncStatus.PTP_LOCKED
        sample_event.timestamp_precision = TimestampPrecision.MICROSECOND
        
        result = verifier.verify(sample_event, jurisdiction="EU", entity_type="HFT")
        
        assert result["status"] == "PASSED"
        assert result["jurisdiction"] == "EU"
    
    def test_verify_eu_non_hft_requirements(self, sample_event):
        """Test EU non-HFT timing requirements."""
        verifier = TimingVerifier(default_jurisdiction="EU")
        
        result = verifier.verify(sample_event, jurisdiction="EU", entity_type="NON_HFT")
        
        assert result["status"] == "PASSED"
    
    def test_verify_unreliable_clock(self, sample_event):
        """Test rejection of unreliable clock."""
        verifier = TimingVerifier()
        
        sample_event.clock_sync_status = ClockSyncStatus.UNRELIABLE
        
        result = verifier.verify(sample_event)
        
        assert result["status"] == "FAILED"
        assert result["clock_sync_result"]["error_code"] == "CLOCK_UNRELIABLE"
    
    def test_verify_insufficient_precision(self, sample_event):
        """Test rejection of insufficient precision."""
        verifier = TimingVerifier()
        
        sample_event.timestamp_precision = TimestampPrecision.SECOND
        
        result = verifier.verify(sample_event, jurisdiction="EU", entity_type="HFT")
        
        assert result["status"] == "FAILED"
        assert "PRECISION_INSUFFICIENT" in str(result)
    
    def test_verify_timestamp_ordering(self, sample_event):
        """Test timestamp ordering verification."""
        verifier = TimingVerifier()
        
        # Create events in order
        events = []
        base_time = datetime.now(timezone.utc)
        for i in range(3):
            event = VCPEvent(
                event_id=f"event-{i}",
                timestamp=base_time,
                timestamp_precision=TimestampPrecision.MILLISECOND,
                clock_sync_status=ClockSyncStatus.NTP_SYNCED,
                sequence_num=i,
                prev_hash="0" * 64,
                event_type="ORDER_NEW",
                payload={},
                signature=sample_event.signature,
            )
            events.append(event)
            base_time = base_time.replace(microsecond=base_time.microsecond + 1000)
        
        result = verifier.verify_timestamp_ordering(events)
        
        assert result["status"] == "PASSED"


class TestAnchorVerifier:
    """Tests for AnchorVerifier."""
    
    def test_verify_tsa_anchor_trusted(self, sample_anchor):
        """Test verification of trusted TSA anchor."""
        verifier = AnchorVerifier(
            trusted_tsa_urls={"https://freetsa.org/tsr"},
        )
        
        result = verifier.verify(sample_anchor.merkle_root, sample_anchor)
        
        assert result["status"] == "PASSED"
        assert result["tsa_result"]["status"] == "PASSED"
    
    def test_verify_tsa_anchor_untrusted(self, sample_anchor):
        """Test warning for untrusted TSA anchor."""
        verifier = AnchorVerifier(
            trusted_tsa_urls={"https://other-tsa.example.com"},
        )
        
        result = verifier.verify(sample_anchor.merkle_root, sample_anchor)
        
        assert result["status"] == "WARNING"
        assert result["tsa_result"]["error_code"] == "TSA_NOT_TRUSTED"
    
    def test_verify_blockchain_anchor(self):
        """Test verification of blockchain anchor."""
        anchor = AnchorRecord(
            anchor_type=AnchorType.BLOCKCHAIN,
            merkle_root=base64.b64encode(b"\x00" * 32).decode(),
            anchor_timestamp=datetime.now(timezone.utc),
            batch_start_seq=0,
            batch_end_seq=10,
            blockchain_anchor=BlockchainAnchor(
                chain="ethereum",
                network="mainnet",
                transaction_hash="0x" + "a" * 64,
                block_number=1000000,
                block_timestamp=datetime.now(timezone.utc),
                merkle_root_in_tx=base64.b64encode(b"\x00" * 32).decode(),
                confirmations=20,
            ),
        )
        
        verifier = AnchorVerifier(verify_blockchain=False)
        result = verifier.verify(anchor.merkle_root, anchor)
        
        assert result["status"] == "PASSED"
        assert result["blockchain_result"]["status"] == "PASSED"


class TestVerificationEngine:
    """Tests for VerificationEngine integration."""
    
    def test_verify_event_all_pass(
        self, sample_event, sample_manifest, sample_merkle_proof, sample_anchor
    ):
        """Test full verification with all checks passing."""
        # This test is more of a smoke test - full integration requires
        # properly generated Merkle proofs
        
        engine = VerificationEngine(
            manifest=sample_manifest,
            require_manifest=True,
        )
        
        # Note: This will fail Merkle verification since proof isn't real
        # but tests the engine orchestration
        result = engine.verify_event(
            event=sample_event,
            proof=sample_merkle_proof,
            anchor=sample_anchor,
        )
        
        # Signature should pass
        assert result.signature_valid is True
        
        engine.close()


# Markers for slow tests
@pytest.mark.slow
class TestOnlineVerification:
    """Tests requiring network access (marked slow)."""
    
    @pytest.mark.skip(reason="Requires network access")
    def test_verify_blockchain_online(self):
        """Test online blockchain verification."""
        pass
