"""
Verification Engine - Core orchestration for VCP verification.

This module provides the main VerificationEngine class that orchestrates
all individual verification components (signature, Merkle, anchor, timing)
to provide comprehensive verification of VCP events.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import structlog

from vcp_supervision.models import (
    AnchorRecord,
    MerkleProof,
    PublicKeyManifest,
    VCPEvent,
    VerificationResult,
    VerificationStatus,
)
from vcp_supervision.verification.anchor import AnchorVerifier
from vcp_supervision.verification.merkle import MerkleVerifier
from vcp_supervision.verification.signature import SignatureVerifier
from vcp_supervision.verification.timing import TimingVerifier

if TYPE_CHECKING:
    pass

logger = structlog.get_logger(__name__)


class VerificationEngine:
    """
    Main verification engine for VCP Supervision Node.
    
    Orchestrates all verification components to provide comprehensive
    verification of VCP events, including:
    - Digital signature verification (Ed25519)
    - Merkle proof verification (RFC 6962)
    - External anchor verification (TSA/Blockchain)
    - Timing requirements verification (RTS 25/CAT)
    
    The engine aggregates results from all components and produces
    a unified verification result with compliance scoring.
    """
    
    def __init__(
        self,
        manifest: PublicKeyManifest | None = None,
        default_jurisdiction: str = "EU",
        require_manifest: bool = True,
        verify_blockchain_online: bool = False,
        trusted_tsa_urls: set[str] | None = None,
        blockchain_rpc_urls: dict[str, str] | None = None,
    ) -> None:
        """
        Initialize the verification engine.
        
        Args:
            manifest: Public key manifest for signature verification
            default_jurisdiction: Default jurisdiction for timing checks
            require_manifest: Whether to require keys in manifest
            verify_blockchain_online: Whether to verify blockchain anchors online
            trusted_tsa_urls: Set of trusted TSA URLs
            blockchain_rpc_urls: Mapping of chain name to RPC URL
        """
        self._logger = logger.bind(component="VerificationEngine")
        
        # Initialize component verifiers
        self.signature_verifier = SignatureVerifier(
            manifest=manifest,
            require_manifest=require_manifest,
        )
        self.merkle_verifier = MerkleVerifier()
        self.anchor_verifier = AnchorVerifier(
            trusted_tsa_urls=trusted_tsa_urls,
            verify_blockchain=verify_blockchain_online,
            blockchain_rpc_urls=blockchain_rpc_urls,
        )
        self.timing_verifier = TimingVerifier(
            default_jurisdiction=default_jurisdiction,
        )
        
        self.default_jurisdiction = default_jurisdiction
        self._logger.info(
            "Verification engine initialized",
            jurisdiction=default_jurisdiction,
            require_manifest=require_manifest,
        )
    
    def verify_event(
        self,
        event: VCPEvent,
        proof: MerkleProof,
        anchor: AnchorRecord,
        jurisdiction: str | None = None,
        entity_type: str = "NON_HFT",
    ) -> VerificationResult:
        """
        Verify a single VCP event with its Merkle proof and anchor.
        
        This is the main entry point for event verification. It performs
        all verification checks and returns a comprehensive result.
        
        Args:
            event: The VCP event to verify
            proof: Merkle inclusion proof for the event
            anchor: External anchor record
            jurisdiction: Target jurisdiction (default: self.default_jurisdiction)
            entity_type: Entity type for timing requirements
            
        Returns:
            VerificationResult with status and details
        """
        jurisdiction = jurisdiction or self.default_jurisdiction
        started_at = datetime.now(timezone.utc)
        start_time = time.perf_counter()
        
        self._logger.info(
            "Starting event verification",
            event_id=event.event_id,
            jurisdiction=jurisdiction,
            entity_type=entity_type,
        )
        
        # Perform all verifications
        results = {
            "signature": self.signature_verifier.verify(event),
            "merkle": self.merkle_verifier.verify(event, proof),
            "anchor": self.anchor_verifier.verify(anchor.merkle_root, anchor),
            "timing": self.timing_verifier.verify(event, jurisdiction, entity_type),
        }
        
        # Calculate elapsed time
        elapsed = time.perf_counter() - start_time
        completed_at = datetime.now(timezone.utc)
        
        # Aggregate results
        return self._aggregate_results(
            event=event,
            results=results,
            jurisdiction=jurisdiction,
            started_at=started_at,
            completed_at=completed_at,
            elapsed=elapsed,
        )
    
    def verify_batch(
        self,
        events: list[VCPEvent],
        proofs: list[MerkleProof],
        anchor: AnchorRecord,
        jurisdiction: str | None = None,
        entity_type: str = "NON_HFT",
    ) -> list[VerificationResult]:
        """
        Verify a batch of VCP events.
        
        Args:
            events: List of VCP events to verify
            proofs: List of Merkle proofs (one per event)
            anchor: Shared anchor record for the batch
            jurisdiction: Target jurisdiction
            entity_type: Entity type for timing requirements
            
        Returns:
            List of VerificationResults (one per event)
        """
        if len(events) != len(proofs):
            raise ValueError("Number of events must match number of proofs")
        
        self._logger.info(
            "Starting batch verification",
            num_events=len(events),
            jurisdiction=jurisdiction or self.default_jurisdiction,
        )
        
        results = []
        for event, proof in zip(events, proofs):
            result = self.verify_event(
                event=event,
                proof=proof,
                anchor=anchor,
                jurisdiction=jurisdiction,
                entity_type=entity_type,
            )
            results.append(result)
        
        # Also verify batch completeness
        completeness_result = self.merkle_verifier.verify_batch_completeness(
            events=events,
            start_seq=anchor.batch_start_seq,
            end_seq=anchor.batch_end_seq,
        )
        
        if completeness_result["status"] != "PASSED":
            self._logger.warning(
                "Batch completeness check failed",
                error_code=completeness_result.get("error_code"),
            )
        
        # Verify timestamp ordering
        ordering_result = self.timing_verifier.verify_timestamp_ordering(events)
        
        if ordering_result["status"] != "PASSED":
            self._logger.warning(
                "Timestamp ordering check failed",
                error_code=ordering_result.get("error_code"),
            )
        
        return results
    
    def _aggregate_results(
        self,
        event: VCPEvent,
        results: dict[str, dict],
        jurisdiction: str,
        started_at: datetime,
        completed_at: datetime,
        elapsed: float,
    ) -> VerificationResult:
        """
        Aggregate verification results into a single VerificationResult.
        
        Args:
            event: The verified event
            results: Dictionary of component results
            jurisdiction: Target jurisdiction
            started_at: Verification start time
            completed_at: Verification completion time
            elapsed: Elapsed time in seconds
            
        Returns:
            Aggregated VerificationResult
        """
        # Extract individual statuses
        sig_status = results["signature"]["status"]
        merkle_status = results["merkle"]["status"]
        anchor_status = results["anchor"]["status"]
        timing_status = results["timing"]["status"]
        
        # Determine overall status
        all_statuses = [sig_status, merkle_status, anchor_status, timing_status]
        
        if "FAILED" in all_statuses:
            overall_status = VerificationStatus.FAILED
        elif "WARNING" in all_statuses:
            overall_status = VerificationStatus.WARNING
        else:
            overall_status = VerificationStatus.PASSED
        
        # Calculate compliance score
        score = self._calculate_compliance_score(results)
        
        # Collect warnings
        warnings = []
        for component, result in results.items():
            if result["status"] == "WARNING":
                warnings.append(f"{component}: {result.get('message', 'Unknown warning')}")
        
        # Determine error code if failed
        error_code = None
        message = None
        if overall_status == VerificationStatus.FAILED:
            for component, result in results.items():
                if result["status"] == "FAILED":
                    error_code = result.get("error_code")
                    message = result.get("message")
                    break
        
        self._logger.info(
            "Verification completed",
            event_id=event.event_id,
            status=overall_status.value,
            score=score,
            elapsed_seconds=elapsed,
        )
        
        return VerificationResult(
            status=overall_status,
            error_code=error_code,
            message=message,
            signature_valid=sig_status == "PASSED",
            merkle_valid=merkle_status == "PASSED",
            anchor_valid=anchor_status in ("PASSED", "WARNING"),
            timing_valid=timing_status in ("PASSED", "WARNING"),
            jurisdiction=jurisdiction,
            compliance_score=score,
            verification_started_at=started_at,
            verification_completed_at=completed_at,
            elapsed_seconds=elapsed,
            warnings=warnings,
            details={
                "signature": results["signature"],
                "merkle": results["merkle"],
                "anchor": results["anchor"],
                "timing": results["timing"],
            },
        )
    
    def _calculate_compliance_score(self, results: dict[str, dict]) -> float:
        """
        Calculate a compliance score based on verification results.
        
        Score breakdown:
        - Signature: 30%
        - Merkle proof: 25%
        - External anchor: 25%
        - Timing compliance: 20%
        
        Args:
            results: Dictionary of component results
            
        Returns:
            Compliance score between 0.0 and 1.0
        """
        weights = {
            "signature": 0.30,
            "merkle": 0.25,
            "anchor": 0.25,
            "timing": 0.20,
        }
        
        status_scores = {
            "PASSED": 1.0,
            "WARNING": 0.7,
            "FAILED": 0.0,
        }
        
        total_score = 0.0
        for component, weight in weights.items():
            status = results[component]["status"]
            component_score = status_scores.get(status, 0.0)
            total_score += weight * component_score
        
        return round(total_score, 3)
    
    def update_manifest(self, manifest: PublicKeyManifest) -> None:
        """
        Update the public key manifest.
        
        Args:
            manifest: New public key manifest
        """
        self.signature_verifier.update_manifest(manifest)
        self._logger.info(
            "Manifest updated",
            manifest_id=manifest.manifest_id,
            version=manifest.version,
        )
    
    def close(self) -> None:
        """Close any open resources."""
        self.anchor_verifier.close()
    
    def __enter__(self) -> "VerificationEngine":
        return self
    
    def __exit__(self, *args) -> None:
        self.close()
