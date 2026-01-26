"""
VCP Supervision Node - Main entry point.

This module provides the SupervisionNode class which serves as the main
interface for regulatory authorities to verify VCP-compliant audit trails.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog
import yaml

from vcp_supervision.models import (
    AnchorRecord,
    ComplianceReport,
    MerkleProof,
    PublicKeyManifest,
    VCPEvent,
    VerificationResult,
)
from vcp_supervision.verification import VerificationEngine

if TYPE_CHECKING:
    pass

logger = structlog.get_logger(__name__)


class SupervisionNode:
    """
    VCP Supervision Node - Independent verification infrastructure.
    
    This class provides the main interface for regulatory authorities
    to verify VCP-compliant algorithmic trading audit trails.
    
    Key Features:
    - Independent verification of VCP events
    - Multi-jurisdiction compliance checking
    - Batch verification with completeness checks
    - Compliance report generation
    - DORA incident reporting support
    
    Example:
        >>> node = SupervisionNode(config_path="config/default.yaml")
        >>> result = node.verify_event(event, proof, anchor)
        >>> print(f"Status: {result.status}, Score: {result.compliance_score}")
    """
    
    def __init__(
        self,
        config_path: str | Path | None = None,
        config: dict[str, Any] | None = None,
        manifest: PublicKeyManifest | None = None,
    ) -> None:
        """
        Initialize the Supervision Node.
        
        Args:
            config_path: Path to YAML configuration file
            config: Configuration dictionary (overrides config_path)
            manifest: Initial public key manifest
        """
        self._logger = logger.bind(component="SupervisionNode")
        
        # Load configuration
        self.config = self._load_config(config_path, config)
        
        # Initialize verification engine
        self.engine = VerificationEngine(
            manifest=manifest,
            default_jurisdiction=self.config.get("verification", {}).get(
                "timing", {}
            ).get("default_jurisdiction", "EU"),
            require_manifest=self.config.get("verification", {}).get(
                "signature", {}
            ).get("require_manifest", True),
            verify_blockchain_online=self.config.get("verification", {}).get(
                "anchor", {}
            ).get("verify_blockchain_online", False),
        )
        
        # Statistics
        self._stats = {
            "events_verified": 0,
            "events_passed": 0,
            "events_failed": 0,
            "events_warning": 0,
            "started_at": datetime.now(timezone.utc),
        }
        
        self._logger.info(
            "Supervision Node initialized",
            config_path=str(config_path) if config_path else None,
        )
    
    def _load_config(
        self,
        config_path: str | Path | None,
        config: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """
        Load configuration from file or dictionary.
        
        Args:
            config_path: Path to YAML configuration file
            config: Configuration dictionary
            
        Returns:
            Configuration dictionary
        """
        if config is not None:
            return config
        
        if config_path is not None:
            path = Path(config_path)
            if path.exists():
                with open(path) as f:
                    return yaml.safe_load(f)
            else:
                self._logger.warning("Config file not found", path=str(path))
        
        # Return default configuration
        return self._default_config()
    
    def _default_config(self) -> dict[str, Any]:
        """Return default configuration."""
        return {
            "verification": {
                "signature": {
                    "algorithm": "Ed25519",
                    "require_manifest": True,
                },
                "merkle": {
                    "hash_algorithm": "SHA-256",
                    "rfc6962_compliant": True,
                },
                "anchor": {
                    "verify_blockchain_online": False,
                },
                "timing": {
                    "default_jurisdiction": "EU",
                },
            },
            "reporting": {
                "dora": {
                    "initial_report_target_hours": 4,
                    "intermediate_report_hours": 72,
                },
                "fca": {
                    "submission_deadline_days": 14,
                },
            },
        }
    
    def verify_event(
        self,
        event: VCPEvent,
        proof: MerkleProof,
        anchor: AnchorRecord,
        jurisdiction: str | None = None,
        entity_type: str = "NON_HFT",
    ) -> VerificationResult:
        """
        Verify a single VCP event.
        
        Args:
            event: The VCP event to verify
            proof: Merkle inclusion proof
            anchor: External anchor record
            jurisdiction: Target jurisdiction (default from config)
            entity_type: Entity type for timing requirements
            
        Returns:
            VerificationResult with status and details
        """
        result = self.engine.verify_event(
            event=event,
            proof=proof,
            anchor=anchor,
            jurisdiction=jurisdiction,
            entity_type=entity_type,
        )
        
        # Update statistics
        self._update_stats(result)
        
        return result
    
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
            events: List of VCP events
            proofs: List of Merkle proofs
            anchor: Shared anchor record
            jurisdiction: Target jurisdiction
            entity_type: Entity type for timing requirements
            
        Returns:
            List of VerificationResults
        """
        results = self.engine.verify_batch(
            events=events,
            proofs=proofs,
            anchor=anchor,
            jurisdiction=jurisdiction,
            entity_type=entity_type,
        )
        
        # Update statistics
        for result in results:
            self._update_stats(result)
        
        return results
    
    def generate_compliance_report(
        self,
        results: list[VerificationResult],
        jurisdiction: str,
        report_id: str | None = None,
    ) -> ComplianceReport:
        """
        Generate a compliance report from verification results.
        
        Args:
            results: List of verification results
            jurisdiction: Target jurisdiction
            report_id: Optional report identifier
            
        Returns:
            ComplianceReport for regulatory submission
        """
        from uuid import uuid4
        
        report_id = report_id or str(uuid4())
        
        # Calculate statistics
        total = len(results)
        passed = sum(1 for r in results if r.status.value == "PASSED")
        failed = sum(1 for r in results if r.status.value == "FAILED")
        warning = sum(1 for r in results if r.status.value == "WARNING")
        
        # Calculate scores
        if total > 0:
            overall_score = sum(r.compliance_score for r in results) / total
            integrity_score = sum(
                1 for r in results if r.signature_valid and r.merkle_valid
            ) / total
            completeness_score = passed / total
            timing_score = sum(1 for r in results if r.timing_valid) / total
        else:
            overall_score = 0.0
            integrity_score = 0.0
            completeness_score = 0.0
            timing_score = 0.0
        
        # Collect issues
        issues = []
        for result in results:
            if result.status.value == "FAILED":
                issues.append(f"{result.error_code}: {result.message}")
            for warning in result.warnings:
                issues.append(f"WARNING: {warning}")
        
        # Determine regulations checked based on jurisdiction
        regulations = self._get_regulations_for_jurisdiction(jurisdiction)
        
        return ComplianceReport(
            report_id=report_id,
            generated_at=datetime.now(timezone.utc),
            jurisdiction=jurisdiction,
            total_events=total,
            passed_events=passed,
            failed_events=failed,
            warning_events=warning,
            overall_score=round(overall_score, 3),
            integrity_score=round(integrity_score, 3),
            completeness_score=round(completeness_score, 3),
            timing_score=round(timing_score, 3),
            issues=issues,
            regulations_checked=regulations,
        )
    
    def _get_regulations_for_jurisdiction(self, jurisdiction: str) -> list[str]:
        """Get list of regulations checked for a jurisdiction."""
        regulations_map = {
            "EU": [
                "MiFID II (2014/65/EU)",
                "RTS 25 (2017/574)",
                "DORA (2022/2554)",
                "eIDAS (910/2014)",
            ],
            "UK": [
                "UK MiFID II",
                "UK RTS 25",
                "FCA MAR 7A",
                "PS21/3",
            ],
            "US": [
                "SEC Rule 17a-4",
                "CAT NMS Plan",
                "Regulation SCI",
            ],
            "JP": [
                "FIEA",
                "Cabinet Office Ordinance 338",
            ],
            "SG": [
                "MAS TRM Guidelines",
            ],
            "HK": [
                "SFC Electronic Trading Guidelines",
            ],
            "AU": [
                "ASIC Market Integrity Rules",
            ],
            "CA": [
                "NI 23-103",
                "UMIR",
            ],
            "CH": [
                "FINMA Circular 2013/8",
            ],
        }
        return regulations_map.get(jurisdiction, [])
    
    def _update_stats(self, result: VerificationResult) -> None:
        """Update internal statistics."""
        self._stats["events_verified"] += 1
        if result.status.value == "PASSED":
            self._stats["events_passed"] += 1
        elif result.status.value == "FAILED":
            self._stats["events_failed"] += 1
        else:
            self._stats["events_warning"] += 1
    
    def get_stats(self) -> dict[str, Any]:
        """
        Get verification statistics.
        
        Returns:
            Dictionary of statistics
        """
        stats = self._stats.copy()
        stats["uptime_seconds"] = (
            datetime.now(timezone.utc) - stats["started_at"]
        ).total_seconds()
        return stats
    
    def update_manifest(self, manifest: PublicKeyManifest) -> None:
        """
        Update the public key manifest.
        
        Args:
            manifest: New public key manifest
        """
        self.engine.update_manifest(manifest)
    
    def close(self) -> None:
        """Close the supervision node and release resources."""
        self.engine.close()
        self._logger.info(
            "Supervision Node closed",
            events_verified=self._stats["events_verified"],
        )
    
    def __enter__(self) -> "SupervisionNode":
        return self
    
    def __exit__(self, *args) -> None:
        self.close()
