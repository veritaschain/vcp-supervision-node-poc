"""
Timing requirements verification module.

Implements verification of timestamp precision and clock synchronization
requirements across multiple jurisdictions (EU RTS 25, US CAT, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from vcp_supervision.models import ClockSyncStatus, Jurisdiction, TimestampPrecision, VCPEvent

logger = structlog.get_logger(__name__)


class EntityType(str, Enum):
    """Entity type for determining applicable requirements."""
    
    HFT = "HFT"                    # High-frequency trader
    NON_HFT = "NON_HFT"            # Non-HFT investment firm
    EXCHANGE = "EXCHANGE"          # Exchange/trading venue
    BROKER_DEALER = "BD"           # US broker-dealer
    SRO = "SRO"                    # Self-regulatory organization


@dataclass
class TimingRequirement:
    """Timing requirement specification for a jurisdiction/entity type."""
    
    jurisdiction: str
    entity_type: str
    max_utc_divergence_us: int | None  # Maximum UTC divergence in microseconds
    max_utc_divergence_ms: int | None  # Maximum UTC divergence in milliseconds
    min_precision: str                  # Minimum timestamp precision
    require_traceability: bool         # Whether traceability documentation required
    annual_review_required: bool       # Whether annual clock audit required
    evidence_grade: str                # Regulatory evidence grade
    regulation_reference: str          # Primary regulation reference


class TimingVerifier:
    """
    Timing requirements verifier for multi-jurisdiction compliance.
    
    Verifies that VCP events meet timestamp precision and clock synchronization
    requirements for the target jurisdiction(s).
    
    Regulatory Alignment:
    - EU RTS 25: 100µs for HFT, 1ms for non-HFT
    - UK RTS 25: Same as EU (onshored)
    - US CAT NMS: 50ms for BDs, 100µs for SROs, nanosecond granularity
    - Japan FIEA: Millisecond recommended
    - Singapore MAS TRM: 1 second
    
    Evidence Grades:
    - Primary Law (RTS): EU RTS 25, UK RTS 25
    - Primary Law: US CAT Rule 613
    - Regulator Guidance: Japan, Singapore, Hong Kong
    """
    
    # Jurisdiction-specific timing requirements
    REQUIREMENTS: dict[str, dict[str, TimingRequirement]] = {
        "EU": {
            "HFT": TimingRequirement(
                jurisdiction="EU",
                entity_type="HFT",
                max_utc_divergence_us=100,
                max_utc_divergence_ms=None,
                min_precision="MICROSECOND",
                require_traceability=True,
                annual_review_required=True,
                evidence_grade="Primary Law (RTS)",
                regulation_reference="RTS 25 Article 1-4",
            ),
            "NON_HFT": TimingRequirement(
                jurisdiction="EU",
                entity_type="NON_HFT",
                max_utc_divergence_us=1000,
                max_utc_divergence_ms=1,
                min_precision="MILLISECOND",
                require_traceability=True,
                annual_review_required=True,
                evidence_grade="Primary Law (RTS)",
                regulation_reference="RTS 25 Article 1-4",
            ),
        },
        "UK": {
            "HFT": TimingRequirement(
                jurisdiction="UK",
                entity_type="HFT",
                max_utc_divergence_us=100,
                max_utc_divergence_ms=None,
                min_precision="MICROSECOND",
                require_traceability=True,
                annual_review_required=True,
                evidence_grade="Primary Law",
                regulation_reference="UK RTS 25 (onshored)",
            ),
            "NON_HFT": TimingRequirement(
                jurisdiction="UK",
                entity_type="NON_HFT",
                max_utc_divergence_us=1000,
                max_utc_divergence_ms=1,
                min_precision="MILLISECOND",
                require_traceability=True,
                annual_review_required=True,
                evidence_grade="Primary Law",
                regulation_reference="UK RTS 25 (onshored)",
            ),
        },
        "US": {
            "EXCHANGE": TimingRequirement(
                jurisdiction="US",
                entity_type="EXCHANGE",
                max_utc_divergence_us=100,
                max_utc_divergence_ms=None,
                min_precision="NANOSECOND",
                require_traceability=True,
                annual_review_required=False,
                evidence_grade="Primary Law",
                regulation_reference="CAT NMS Plan",
            ),
            "BD": TimingRequirement(
                jurisdiction="US",
                entity_type="BD",
                max_utc_divergence_us=None,
                max_utc_divergence_ms=50,
                min_precision="MILLISECOND",
                require_traceability=True,
                annual_review_required=False,
                evidence_grade="Primary Law",
                regulation_reference="CAT NMS Plan / FINRA 4590",
            ),
            "SRO": TimingRequirement(
                jurisdiction="US",
                entity_type="SRO",
                max_utc_divergence_us=100,
                max_utc_divergence_ms=None,
                min_precision="NANOSECOND",
                require_traceability=True,
                annual_review_required=False,
                evidence_grade="Primary Law",
                regulation_reference="CAT NMS Plan",
            ),
        },
        "JP": {
            "ALL": TimingRequirement(
                jurisdiction="JP",
                entity_type="ALL",
                max_utc_divergence_us=None,
                max_utc_divergence_ms=None,
                min_precision="MILLISECOND",
                require_traceability=False,
                annual_review_required=False,
                evidence_grade="Regulator Guidance",
                regulation_reference="FIEA / FSA Guidelines",
            ),
        },
        "SG": {
            "ALL": TimingRequirement(
                jurisdiction="SG",
                entity_type="ALL",
                max_utc_divergence_us=None,
                max_utc_divergence_ms=1000,
                min_precision="SECOND",
                require_traceability=False,
                annual_review_required=False,
                evidence_grade="Regulator Guidance",
                regulation_reference="MAS TRM Guidelines",
            ),
        },
        "HK": {
            "HFT": TimingRequirement(
                jurisdiction="HK",
                entity_type="HFT",
                max_utc_divergence_us=None,
                max_utc_divergence_ms=None,
                min_precision="MICROSECOND",
                require_traceability=False,
                annual_review_required=False,
                evidence_grade="Regulator Guidance",
                regulation_reference="SFC Electronic Trading Guidelines",
            ),
            "NON_HFT": TimingRequirement(
                jurisdiction="HK",
                entity_type="NON_HFT",
                max_utc_divergence_us=None,
                max_utc_divergence_ms=None,
                min_precision="MILLISECOND",
                require_traceability=False,
                annual_review_required=False,
                evidence_grade="Regulator Guidance",
                regulation_reference="SFC Electronic Trading Guidelines",
            ),
        },
        "AU": {
            "ALL": TimingRequirement(
                jurisdiction="AU",
                entity_type="ALL",
                max_utc_divergence_us=100,  # RTS 25 aligned
                max_utc_divergence_ms=1,
                min_precision="MILLISECOND",
                require_traceability=True,
                annual_review_required=False,
                evidence_grade="Primary Law",
                regulation_reference="ASIC Market Integrity Rules",
            ),
        },
        "CA": {
            "ALL": TimingRequirement(
                jurisdiction="CA",
                entity_type="ALL",
                max_utc_divergence_us=None,
                max_utc_divergence_ms=50,
                min_precision="MILLISECOND",
                require_traceability=True,
                annual_review_required=False,
                evidence_grade="Primary Law",
                regulation_reference="NI 23-103 / UMIR 10.14",
            ),
        },
        "CH": {
            "ALL": TimingRequirement(
                jurisdiction="CH",
                entity_type="ALL",
                max_utc_divergence_us=100,  # MiFID-like
                max_utc_divergence_ms=1,
                min_precision="MILLISECOND",
                require_traceability=True,
                annual_review_required=False,
                evidence_grade="Regulator Guidance",
                regulation_reference="FINMA Circular 2013/8",
            ),
        },
    }
    
    # Precision ordering (most precise first)
    PRECISION_ORDER = ["NANOSECOND", "MICROSECOND", "MILLISECOND", "SECOND"]
    
    # Clock sync status to expected precision mapping
    CLOCK_SYNC_PRECISION = {
        "PTP_LOCKED": "MICROSECOND",     # PTP typically <1µs
        "NTP_SYNCED": "MILLISECOND",     # NTP typically <1ms
        "BEST_EFFORT": "SECOND",         # Best effort, may be >1s
        "UNRELIABLE": None,              # Cannot rely on timing
    }
    
    def __init__(self, default_jurisdiction: str = "EU") -> None:
        """
        Initialize the timing verifier.
        
        Args:
            default_jurisdiction: Default jurisdiction for verification
        """
        self.default_jurisdiction = default_jurisdiction
        self._logger = logger.bind(component="TimingVerifier")
    
    def verify(
        self,
        event: VCPEvent,
        jurisdiction: str | None = None,
        entity_type: str = "NON_HFT",
    ) -> dict[str, any]:
        """
        Verify timing requirements for a VCP event.
        
        Args:
            event: The VCP event to verify
            jurisdiction: Target jurisdiction (default: self.default_jurisdiction)
            entity_type: Entity type (HFT, NON_HFT, BD, etc.)
            
        Returns:
            Verification result dictionary
        """
        jurisdiction = jurisdiction or self.default_jurisdiction
        
        self._logger.debug(
            "Verifying timing requirements",
            event_id=event.event_id,
            jurisdiction=jurisdiction,
            entity_type=entity_type,
        )
        
        # Get applicable requirements
        requirement = self._get_requirement(jurisdiction, entity_type)
        if not requirement:
            return {
                "status": "WARNING",
                "error_code": "NO_REQUIREMENT",
                "message": f"No timing requirement found for {jurisdiction}/{entity_type}",
            }
        
        results = {
            "clock_sync": self._verify_clock_sync(event, requirement),
            "precision": self._verify_precision(event, requirement),
            "traceability": self._check_traceability_requirement(requirement),
        }
        
        # Aggregate results
        return self._aggregate_results(event, requirement, results)
    
    def _get_requirement(
        self,
        jurisdiction: str,
        entity_type: str,
    ) -> TimingRequirement | None:
        """Get the applicable timing requirement."""
        jurisdiction_reqs = self.REQUIREMENTS.get(jurisdiction)
        if not jurisdiction_reqs:
            return None
        
        # Try specific entity type, then fall back to ALL
        return jurisdiction_reqs.get(entity_type) or jurisdiction_reqs.get("ALL")
    
    def _verify_clock_sync(
        self,
        event: VCPEvent,
        requirement: TimingRequirement,
    ) -> dict[str, any]:
        """
        Verify clock synchronization status.
        
        Args:
            event: The VCP event
            requirement: Applicable timing requirement
            
        Returns:
            Clock sync verification result
        """
        clock_status = event.clock_sync_status.value
        
        # UNRELIABLE is always a failure for regulated entities
        if clock_status == "UNRELIABLE":
            return {
                "status": "FAILED",
                "error_code": "CLOCK_UNRELIABLE",
                "message": "Clock synchronization is unreliable",
                "clock_sync_status": clock_status,
            }
        
        # Check if clock sync status is adequate for the requirement
        expected_precision = self.CLOCK_SYNC_PRECISION.get(clock_status)
        if not expected_precision:
            return {
                "status": "WARNING",
                "error_code": "CLOCK_UNKNOWN",
                "message": f"Unknown clock sync status: {clock_status}",
            }
        
        min_precision = requirement.min_precision
        
        # Check if clock sync provides adequate precision
        expected_idx = self.PRECISION_ORDER.index(expected_precision)
        required_idx = self.PRECISION_ORDER.index(min_precision)
        
        if expected_idx > required_idx:
            return {
                "status": "WARNING",
                "error_code": "CLOCK_PRECISION_LOW",
                "message": (
                    f"Clock sync ({clock_status}) provides {expected_precision} precision, "
                    f"but {min_precision} is required for {requirement.jurisdiction}"
                ),
                "clock_sync_status": clock_status,
                "expected_precision": expected_precision,
                "required_precision": min_precision,
            }
        
        return {
            "status": "PASSED",
            "clock_sync_status": clock_status,
            "expected_precision": expected_precision,
        }
    
    def _verify_precision(
        self,
        event: VCPEvent,
        requirement: TimingRequirement,
    ) -> dict[str, any]:
        """
        Verify timestamp precision meets requirements.
        
        Args:
            event: The VCP event
            requirement: Applicable timing requirement
            
        Returns:
            Precision verification result
        """
        event_precision = event.timestamp_precision.value
        min_precision = requirement.min_precision
        
        event_idx = self.PRECISION_ORDER.index(event_precision)
        required_idx = self.PRECISION_ORDER.index(min_precision)
        
        if event_idx > required_idx:
            return {
                "status": "FAILED",
                "error_code": "PRECISION_INSUFFICIENT",
                "message": (
                    f"Timestamp precision ({event_precision}) is insufficient. "
                    f"Minimum required: {min_precision}"
                ),
                "event_precision": event_precision,
                "required_precision": min_precision,
                "regulation": requirement.regulation_reference,
            }
        
        return {
            "status": "PASSED",
            "event_precision": event_precision,
            "required_precision": min_precision,
        }
    
    def _check_traceability_requirement(
        self,
        requirement: TimingRequirement,
    ) -> dict[str, any]:
        """
        Check if traceability documentation is required.
        
        Args:
            requirement: Applicable timing requirement
            
        Returns:
            Traceability requirement info
        """
        return {
            "require_traceability": requirement.require_traceability,
            "annual_review_required": requirement.annual_review_required,
            "message": (
                "Annual clock traceability review required"
                if requirement.annual_review_required
                else "No annual review required"
            ),
        }
    
    def _aggregate_results(
        self,
        event: VCPEvent,
        requirement: TimingRequirement,
        results: dict[str, dict],
    ) -> dict[str, any]:
        """
        Aggregate verification results.
        
        Args:
            event: The VCP event
            requirement: Applicable timing requirement
            results: Individual verification results
            
        Returns:
            Aggregated verification result
        """
        statuses = [results["clock_sync"]["status"], results["precision"]["status"]]
        
        if "FAILED" in statuses:
            overall_status = "FAILED"
        elif "WARNING" in statuses:
            overall_status = "WARNING"
        else:
            overall_status = "PASSED"
        
        return {
            "status": overall_status,
            "jurisdiction": requirement.jurisdiction,
            "entity_type": requirement.entity_type,
            "regulation": requirement.regulation_reference,
            "evidence_grade": requirement.evidence_grade,
            "clock_sync_result": results["clock_sync"],
            "precision_result": results["precision"],
            "traceability": results["traceability"],
            "event_timestamp": str(event.timestamp),
        }
    
    def verify_timestamp_ordering(
        self,
        events: list[VCPEvent],
    ) -> dict[str, any]:
        """
        Verify that events are in chronological order.
        
        Args:
            events: List of VCP events to verify
            
        Returns:
            Ordering verification result
        """
        self._logger.debug("Verifying timestamp ordering", num_events=len(events))
        
        if len(events) < 2:
            return {
                "status": "PASSED",
                "message": "Not enough events to verify ordering",
            }
        
        # Sort by sequence number
        sorted_events = sorted(events, key=lambda e: e.sequence_num)
        
        regressions = []
        for i in range(1, len(sorted_events)):
            prev_event = sorted_events[i - 1]
            curr_event = sorted_events[i]
            
            if curr_event.timestamp < prev_event.timestamp:
                regressions.append({
                    "prev_event_id": prev_event.event_id,
                    "prev_seq": prev_event.sequence_num,
                    "prev_timestamp": str(prev_event.timestamp),
                    "curr_event_id": curr_event.event_id,
                    "curr_seq": curr_event.sequence_num,
                    "curr_timestamp": str(curr_event.timestamp),
                    "regression_ms": (
                        prev_event.timestamp - curr_event.timestamp
                    ).total_seconds() * 1000,
                })
        
        if regressions:
            self._logger.warning(
                "Timestamp regressions detected",
                num_regressions=len(regressions),
            )
            return {
                "status": "FAILED",
                "error_code": "TIMESTAMP_REGRESSION",
                "message": f"Found {len(regressions)} timestamp regression(s)",
                "regressions": regressions,
            }
        
        return {
            "status": "PASSED",
            "message": "All events in chronological order",
            "events_checked": len(events),
        }
    
    def get_jurisdiction_requirements(
        self,
        jurisdiction: str,
    ) -> dict[str, TimingRequirement]:
        """
        Get all timing requirements for a jurisdiction.
        
        Args:
            jurisdiction: Jurisdiction code
            
        Returns:
            Dictionary of entity type to requirement
        """
        return self.REQUIREMENTS.get(jurisdiction, {})
    
    def get_all_requirements(self) -> dict[str, dict[str, TimingRequirement]]:
        """
        Get all timing requirements for all jurisdictions.
        
        Returns:
            Nested dictionary of jurisdiction -> entity type -> requirement
        """
        return self.REQUIREMENTS
