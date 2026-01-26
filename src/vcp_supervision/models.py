"""
Data models for VCP Supervision Node.

This module defines the core data structures used throughout the verification process,
aligned with VCP v1.1 specification.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class ClockSyncStatus(str, Enum):
    """Clock synchronization status as defined in VCP v1.1."""
    
    PTP_LOCKED = "PTP_LOCKED"      # IEEE 1588 PTP, <1µs accuracy (Platinum)
    NTP_SYNCED = "NTP_SYNCED"      # NTP synchronized, <1ms accuracy (Gold)
    BEST_EFFORT = "BEST_EFFORT"    # Best effort synchronization (Silver)
    UNRELIABLE = "UNRELIABLE"      # Clock sync unreliable (Warning)


class TimestampPrecision(str, Enum):
    """Timestamp precision levels."""
    
    NANOSECOND = "NANOSECOND"      # 10^-9 seconds
    MICROSECOND = "MICROSECOND"    # 10^-6 seconds
    MILLISECOND = "MILLISECOND"    # 10^-3 seconds
    SECOND = "SECOND"              # 1 second


class AnchorType(str, Enum):
    """External anchor types."""
    
    TSA = "TSA"                    # RFC 3161 Timestamp Authority
    BLOCKCHAIN = "BLOCKCHAIN"      # Blockchain anchor (Ethereum, etc.)
    DUAL = "DUAL"                  # Both TSA and Blockchain


class VerificationStatus(str, Enum):
    """Verification result status."""
    
    PASSED = "PASSED"              # All checks passed
    FAILED = "FAILED"              # Critical check failed
    WARNING = "WARNING"            # Non-critical issue detected
    TIMEOUT = "TIMEOUT"            # Verification timed out


class Jurisdiction(str, Enum):
    """Supported jurisdictions for compliance checking."""
    
    EU = "EU"
    UK = "UK"
    US = "US"
    JP = "JP"
    SG = "SG"
    HK = "HK"
    AU = "AU"
    CA = "CA"
    CH = "CH"


class VCPSignature(BaseModel):
    """Digital signature structure."""
    
    algorithm: str = Field(default="Ed25519", description="Signature algorithm")
    public_key: str = Field(..., description="Base64-encoded public key")
    value: str = Field(..., description="Base64-encoded signature value")
    key_id: Optional[str] = Field(None, description="Key identifier in manifest")


class VCPEvent(BaseModel):
    """
    VCP Event structure aligned with VCP v1.1 specification.
    
    This represents a single auditable event in the algorithmic trading system.
    """
    
    event_id: str = Field(..., description="UUIDv7 event identifier")
    timestamp: datetime = Field(..., description="Event timestamp (ISO 8601)")
    timestamp_precision: TimestampPrecision = Field(
        default=TimestampPrecision.MILLISECOND,
        description="Precision of the timestamp"
    )
    clock_sync_status: ClockSyncStatus = Field(
        default=ClockSyncStatus.NTP_SYNCED,
        description="Clock synchronization status"
    )
    sequence_num: int = Field(..., ge=0, description="Monotonic sequence number")
    prev_hash: str = Field(..., description="Hash of previous event (chain link)")
    event_type: str = Field(..., description="Type of event (ORDER_NEW, FILL, etc.)")
    payload: dict[str, Any] = Field(default_factory=dict, description="Event-specific data")
    signature: VCPSignature = Field(..., description="Digital signature")
    
    # Optional VCP v1.1+ fields
    algorithm_id: Optional[str] = Field(None, description="Algorithm identifier")
    correlation_id: Optional[str] = Field(None, description="Cross-event correlation ID")
    
    @field_validator("event_id")
    @classmethod
    def validate_uuid_format(cls, v: str) -> str:
        """Validate UUIDv7 format."""
        if len(v) != 36 or v.count("-") != 4:
            raise ValueError("event_id must be a valid UUID format")
        return v


class MerkleProof(BaseModel):
    """
    Merkle inclusion proof structure (RFC 6962 compliant).
    
    This proves that a specific event is included in a Merkle tree
    with a known root hash.
    """
    
    leaf_index: int = Field(..., ge=0, description="Index of the leaf in the tree")
    tree_size: int = Field(..., ge=1, description="Total number of leaves in the tree")
    root_hash: str = Field(..., description="Base64-encoded Merkle root hash")
    path: list[str] = Field(..., description="Base64-encoded sibling hashes")
    directions: list[str] = Field(..., description="Direction of each sibling (LEFT/RIGHT)")
    
    @field_validator("directions")
    @classmethod
    def validate_directions(cls, v: list[str]) -> list[str]:
        """Validate direction values."""
        valid_directions = {"LEFT", "RIGHT"}
        for direction in v:
            if direction not in valid_directions:
                raise ValueError(f"Invalid direction: {direction}. Must be LEFT or RIGHT.")
        return v
    
    def __post_init__(self) -> None:
        """Validate path and directions length match."""
        if len(self.path) != len(self.directions):
            raise ValueError("path and directions must have the same length")


class TSAAnchor(BaseModel):
    """RFC 3161 Timestamp Authority anchor."""
    
    tsa_url: str = Field(..., description="TSA service URL")
    token: str = Field(..., description="Base64-encoded TSP response")
    timestamp: datetime = Field(..., description="Timestamp from TSA")
    is_eidas_qualified: bool = Field(
        default=False,
        description="Whether TSA is eIDAS qualified (EU legal presumption)"
    )
    certificate_chain: Optional[list[str]] = Field(
        None,
        description="Base64-encoded certificate chain"
    )


class BlockchainAnchor(BaseModel):
    """Blockchain anchor record."""
    
    chain: str = Field(..., description="Blockchain name (ethereum, polygon, etc.)")
    network: str = Field(..., description="Network (mainnet, goerli, etc.)")
    transaction_hash: str = Field(..., description="Transaction hash")
    block_number: int = Field(..., ge=0, description="Block number")
    block_timestamp: datetime = Field(..., description="Block timestamp")
    merkle_root_in_tx: str = Field(..., description="Merkle root stored in transaction")
    confirmations: int = Field(default=0, ge=0, description="Number of confirmations")


class AnchorRecord(BaseModel):
    """
    External anchor record combining TSA and/or blockchain anchors.
    
    VCP v1.1 requires external anchoring for all tiers.
    """
    
    anchor_type: AnchorType = Field(..., description="Type of anchor")
    merkle_root: str = Field(..., description="Anchored Merkle root")
    anchor_timestamp: datetime = Field(..., description="When the anchor was created")
    batch_start_seq: int = Field(..., ge=0, description="First sequence number in batch")
    batch_end_seq: int = Field(..., ge=0, description="Last sequence number in batch")
    
    tsa_anchor: Optional[TSAAnchor] = Field(None, description="TSA anchor details")
    blockchain_anchor: Optional[BlockchainAnchor] = Field(None, description="Blockchain anchor details")
    
    @field_validator("batch_end_seq")
    @classmethod
    def validate_batch_range(cls, v: int, info: Any) -> int:
        """Validate batch range."""
        if "batch_start_seq" in info.data and v < info.data["batch_start_seq"]:
            raise ValueError("batch_end_seq must be >= batch_start_seq")
        return v


class VerificationResult(BaseModel):
    """
    Result of a verification operation.
    
    Contains the status, any error details, and compliance scores.
    """
    
    status: VerificationStatus = Field(..., description="Overall verification status")
    error_code: Optional[str] = Field(None, description="Error code if failed")
    message: Optional[str] = Field(None, description="Human-readable message")
    
    # Individual check results
    signature_valid: Optional[bool] = Field(None, description="Signature verification result")
    merkle_valid: Optional[bool] = Field(None, description="Merkle proof verification result")
    anchor_valid: Optional[bool] = Field(None, description="Anchor verification result")
    timing_valid: Optional[bool] = Field(None, description="Timing requirements result")
    
    # Compliance details
    jurisdiction: Optional[Jurisdiction] = Field(None, description="Jurisdiction checked")
    compliance_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Compliance score (0-1)")
    
    # Timing information
    verification_started_at: Optional[datetime] = Field(None, description="When verification started")
    verification_completed_at: Optional[datetime] = Field(None, description="When verification completed")
    elapsed_seconds: Optional[float] = Field(None, description="Verification duration in seconds")
    
    # Additional metadata
    warnings: list[str] = Field(default_factory=list, description="Non-critical warnings")
    details: dict[str, Any] = Field(default_factory=dict, description="Additional details")
    
    @property
    def is_compliant(self) -> bool:
        """Check if the result indicates compliance."""
        return self.status in (VerificationStatus.PASSED, VerificationStatus.WARNING)


class PublicKeyManifest(BaseModel):
    """
    Public key manifest for authorized signers.
    
    Regulators maintain a manifest of authorized public keys
    that can be used to verify event signatures.
    """
    
    manifest_id: str = Field(..., description="Manifest identifier")
    version: int = Field(default=1, ge=1, description="Manifest version")
    created_at: datetime = Field(..., description="When manifest was created")
    updated_at: datetime = Field(..., description="When manifest was last updated")
    
    authorized_keys: dict[str, "AuthorizedKey"] = Field(
        default_factory=dict,
        description="Mapping of key fingerprint to key details"
    )


class AuthorizedKey(BaseModel):
    """An authorized public key entry in the manifest."""
    
    fingerprint: str = Field(..., description="Key fingerprint (SHA-256)")
    public_key: str = Field(..., description="Base64-encoded public key")
    algorithm: str = Field(default="Ed25519", description="Key algorithm")
    entity_name: str = Field(..., description="Name of the entity")
    entity_id: str = Field(..., description="Entity identifier (LEI, etc.)")
    valid_from: datetime = Field(..., description="Key validity start")
    valid_until: Optional[datetime] = Field(None, description="Key validity end")
    revoked: bool = Field(default=False, description="Whether key is revoked")
    revoked_at: Optional[datetime] = Field(None, description="When key was revoked")


class ComplianceReport(BaseModel):
    """
    Compliance report for regulatory submission.
    
    Aggregates verification results for a batch of events.
    """
    
    report_id: str = Field(..., description="Report identifier")
    generated_at: datetime = Field(..., description="Report generation timestamp")
    jurisdiction: Jurisdiction = Field(..., description="Target jurisdiction")
    
    # Summary statistics
    total_events: int = Field(..., ge=0, description="Total events verified")
    passed_events: int = Field(..., ge=0, description="Events that passed verification")
    failed_events: int = Field(..., ge=0, description="Events that failed verification")
    warning_events: int = Field(..., ge=0, description="Events with warnings")
    
    # Compliance scores
    overall_score: float = Field(..., ge=0.0, le=1.0, description="Overall compliance score")
    integrity_score: float = Field(..., ge=0.0, le=1.0, description="Integrity score")
    completeness_score: float = Field(..., ge=0.0, le=1.0, description="Completeness score")
    timing_score: float = Field(..., ge=0.0, le=1.0, description="Timing compliance score")
    
    # Issues found
    issues: list[str] = Field(default_factory=list, description="List of issues found")
    
    # Regulatory alignment
    regulations_checked: list[str] = Field(
        default_factory=list,
        description="List of regulations checked"
    )
    
    @property
    def pass_rate(self) -> float:
        """Calculate the pass rate."""
        if self.total_events == 0:
            return 0.0
        return self.passed_events / self.total_events


# Type aliases for convenience
EventBatch = list[VCPEvent]
ProofBatch = list[MerkleProof]
