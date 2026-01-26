"""
Integration tests for VCP Supervision Node.

These tests verify the complete verification flow from event to result.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vcp_supervision import SupervisionNode
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


class TestEndToEndVerification:
    """End-to-end verification tests."""
    
    @pytest.fixture
    def keypair(self):
        """Generate a test keypair."""
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes_raw()
        public_key_b64 = base64.b64encode(public_key_bytes).decode()
        return private_key, public_key_b64
    
    @pytest.fixture
    def manifest(self, keypair):
        """Create a test manifest."""
        _, public_key_b64 = keypair
        key_bytes = base64.b64decode(public_key_b64)
        fingerprint = hashlib.sha256(key_bytes).hexdigest()
        
        return PublicKeyManifest(
            manifest_id="test-manifest",
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
                )
            },
        )
    
    @pytest.fixture
    def signed_event(self, keypair):
        """Create a properly signed event."""
        private_key, public_key_b64 = keypair
        
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
    
    def test_supervision_node_initialization(self):
        """Test SupervisionNode initializes correctly."""
        node = SupervisionNode()
        
        assert node is not None
        stats = node.get_stats()
        assert stats["events_verified"] == 0
        
        node.close()
    
    def test_supervision_node_with_config(self):
        """Test SupervisionNode with custom config."""
        config = {
            "verification": {
                "timing": {"default_jurisdiction": "UK"},
                "signature": {"require_manifest": False},
            }
        }
        
        node = SupervisionNode(config=config)
        assert node.config["verification"]["timing"]["default_jurisdiction"] == "UK"
        
        node.close()
    
    def test_full_verification_flow(self, signed_event, manifest):
        """Test complete verification from event to result."""
        node = SupervisionNode(
            config={
                "verification": {
                    "signature": {"require_manifest": False},
                }
            }
        )
        
        # Create a simple proof (single leaf tree)
        # In real tests, we would compute the proper Merkle root
        event_dict = {
            "event_id": signed_event.event_id,
            "timestamp": signed_event.timestamp.isoformat(),
            "timestamp_precision": signed_event.timestamp_precision.value,
            "clock_sync_status": signed_event.clock_sync_status.value,
            "sequence_num": signed_event.sequence_num,
            "prev_hash": signed_event.prev_hash,
            "event_type": signed_event.event_type,
            "payload": signed_event.payload,
            "signature": {
                "algorithm": signed_event.signature.algorithm,
                "public_key": signed_event.signature.public_key,
                "value": signed_event.signature.value,
            },
        }
        event_bytes = json.dumps(
            event_dict, sort_keys=True, separators=(",", ":")
        ).encode()
        leaf_hash = hashlib.sha256(b"\x00" + event_bytes).digest()
        
        proof = MerkleProof(
            leaf_index=0,
            tree_size=1,
            root_hash=base64.b64encode(leaf_hash).decode(),
            path=[],
            directions=[],
        )
        
        anchor = AnchorRecord(
            anchor_type=AnchorType.TSA,
            merkle_root=base64.b64encode(leaf_hash).decode(),
            anchor_timestamp=datetime.now(timezone.utc),
            batch_start_seq=0,
            batch_end_seq=1,
            tsa_anchor=TSAAnchor(
                tsa_url="https://freetsa.org/tsr",
                token=base64.b64encode(b"mock-token").decode(),
                timestamp=datetime.now(timezone.utc),
                is_eidas_qualified=False,
            ),
        )
        
        # Verify
        result = node.verify_event(
            event=signed_event,
            proof=proof,
            anchor=anchor,
            jurisdiction="EU",
            entity_type="NON_HFT",
        )
        
        # Check result
        assert result.signature_valid is True
        assert result.merkle_valid is True
        assert result.compliance_score > 0
        
        # Check stats updated
        stats = node.get_stats()
        assert stats["events_verified"] == 1
        
        node.close()
    
    def test_compliance_report_generation(self, signed_event, manifest):
        """Test compliance report generation."""
        node = SupervisionNode(
            config={
                "verification": {
                    "signature": {"require_manifest": False},
                }
            }
        )
        
        # Create mock results
        from vcp_supervision.models import VerificationResult, VerificationStatus
        
        results = [
            VerificationResult(
                status=VerificationStatus.PASSED,
                compliance_score=0.95,
                signature_valid=True,
                merkle_valid=True,
                anchor_valid=True,
                timing_valid=True,
            ),
            VerificationResult(
                status=VerificationStatus.PASSED,
                compliance_score=0.90,
                signature_valid=True,
                merkle_valid=True,
                anchor_valid=True,
                timing_valid=True,
            ),
            VerificationResult(
                status=VerificationStatus.FAILED,
                error_code="SIG_INVALID",
                compliance_score=0.0,
                signature_valid=False,
                merkle_valid=True,
                anchor_valid=True,
                timing_valid=True,
            ),
        ]
        
        # Generate report
        report = node.generate_compliance_report(
            results=results,
            jurisdiction="EU",
        )
        
        # Check report
        assert report.total_events == 3
        assert report.passed_events == 2
        assert report.failed_events == 1
        assert report.jurisdiction == "EU"
        assert 0 < report.overall_score < 1
        assert "MiFID II" in report.regulations_checked
        
        node.close()


class TestMultiJurisdictionCompliance:
    """Tests for multi-jurisdiction compliance checking."""
    
    def test_eu_jurisdiction(self):
        """Test EU jurisdiction requirements."""
        node = SupervisionNode(config={
            "verification": {"timing": {"default_jurisdiction": "EU"}}
        })
        
        # EU requires stricter timing for HFT
        timing_reqs = node.engine.timing_verifier.get_jurisdiction_requirements("EU")
        
        assert "HFT" in timing_reqs
        assert timing_reqs["HFT"].max_utc_divergence_us == 100
        assert timing_reqs["HFT"].min_precision == "MICROSECOND"
        
        node.close()
    
    def test_us_jurisdiction(self):
        """Test US jurisdiction requirements."""
        node = SupervisionNode()
        
        timing_reqs = node.engine.timing_verifier.get_jurisdiction_requirements("US")
        
        assert "EXCHANGE" in timing_reqs
        assert "BD" in timing_reqs
        assert timing_reqs["BD"].max_utc_divergence_ms == 50
        
        node.close()
    
    def test_japan_jurisdiction(self):
        """Test Japan jurisdiction requirements."""
        node = SupervisionNode()
        
        timing_reqs = node.engine.timing_verifier.get_jurisdiction_requirements("JP")
        
        assert "ALL" in timing_reqs
        assert timing_reqs["ALL"].min_precision == "MILLISECOND"
        
        node.close()


class TestDORAReporting:
    """Tests for DORA reporting support."""
    
    def test_dora_reporter_initialization(self):
        """Test DORAReporter initializes correctly."""
        from vcp_supervision.reporting import DORAReporter
        
        reporter = DORAReporter()
        
        assert reporter.initial_report_hours == 4
        assert reporter.intermediate_report_hours == 72
        assert reporter.final_report_days == 30
    
    def test_prepare_initial_report(self):
        """Test preparing initial DORA report."""
        from vcp_supervision.reporting import (
            DORAReporter,
            IncidentRecord,
            IncidentCategory,
            IncidentSeverity,
        )
        
        reporter = DORAReporter()
        
        incident = IncidentRecord(
            incident_id="INC-001",
            detected_at=datetime.now(timezone.utc),
            category=IncidentCategory.SYSTEM_FAILURE,
            severity=IncidentSeverity.MAJOR,
            description="Test incident",
            affected_services=["Trading Platform"],
            affected_clients=100,
        )
        
        report = reporter.prepare_initial_report(incident)
        
        assert report.report_type.value == "INITIAL"
        assert report.incident_id == "INC-001"
        assert report.classification["severity"] == "MAJOR"
    
    def test_deadline_checking(self):
        """Test DORA deadline checking."""
        from datetime import timedelta
        from vcp_supervision.reporting import (
            DORAReporter,
            IncidentRecord,
            IncidentCategory,
            IncidentSeverity,
        )
        
        reporter = DORAReporter()
        
        # Create an old incident (past deadline)
        old_incident = IncidentRecord(
            incident_id="INC-OLD",
            detected_at=datetime.now(timezone.utc) - timedelta(hours=24),
            category=IncidentCategory.CYBER_ATTACK,
            severity=IncidentSeverity.MAJOR,
            description="Old incident",
        )
        
        deadlines = reporter.check_reporting_deadlines([old_incident])
        
        assert len(deadlines) == 1
        assert deadlines[0]["initial_report"]["overdue"] is True


@pytest.mark.integration
class TestExternalServices:
    """Tests that require external services (marked for skip in CI)."""
    
    @pytest.mark.skip(reason="Requires external TSA service")
    def test_real_tsa_verification(self):
        """Test verification with real TSA."""
        pass
    
    @pytest.mark.skip(reason="Requires blockchain connection")
    def test_real_blockchain_verification(self):
        """Test verification with real blockchain anchor."""
        pass
