"""
DORA Incident Reporting Support Tools.

Provides data preparation and evidence bundling support for DORA
(Digital Operational Resilience Act) incident reporting requirements.

IMPORTANT: This module provides *support tools* for DORA reporting.
It does NOT generate actual regulatory submissions. Final submissions
must be prepared according to your NCA's specific requirements.

Regulatory Context:
- DORA Article 19: Incident classification
- DORA Article 20: Incident reporting obligations
- DORA Article 21: Harmonisation of content and templates
- DORA Article 22: Centralisation of incident reporting
- DORA Article 23: Feedback from competent authorities

Timeframe Targets (based on ESAs RTS/ITS):
- Initial report: ~4 hours after classification
- Intermediate report: ~72 hours (as needed)
- Final report: ~1 month after resolution

Note: Specific timeframes are defined in ESAs RTS/ITS and may
be subject to updates. Always refer to the latest regulatory text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

import structlog

logger = structlog.get_logger(__name__)


# ============================================================================
# Enumerations
# ============================================================================

class IncidentSeverity(str, Enum):
    """DORA incident severity classification."""
    
    MAJOR = "MAJOR"              # Major ICT-related incident
    SIGNIFICANT = "SIGNIFICANT"  # Significant incident
    MINOR = "MINOR"              # Minor incident


class IncidentCategory(str, Enum):
    """DORA incident category classification."""
    
    CYBER_ATTACK = "CYBER_ATTACK"
    SYSTEM_FAILURE = "SYSTEM_FAILURE"
    THIRD_PARTY = "THIRD_PARTY"
    DATA_BREACH = "DATA_BREACH"
    OPERATIONAL = "OPERATIONAL"
    OTHER = "OTHER"


class ReportType(str, Enum):
    """DORA report type."""
    
    INITIAL = "INITIAL"           # Initial notification
    INTERMEDIATE = "INTERMEDIATE" # Intermediate report
    FINAL = "FINAL"               # Final report


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class IncidentRecord:
    """Record of an ICT-related incident."""
    
    incident_id: str
    detected_at: datetime
    category: IncidentCategory
    severity: IncidentSeverity
    description: str
    
    # Impact assessment
    affected_services: list[str] = field(default_factory=list)
    affected_clients: int = 0
    financial_impact_estimate: float = 0.0
    
    # Root cause (if known)
    root_cause: str | None = None
    root_cause_identified_at: datetime | None = None
    
    # Resolution
    resolved_at: datetime | None = None
    resolution_actions: list[str] = field(default_factory=list)
    
    # VCP correlation
    related_vcp_events: list[str] = field(default_factory=list)
    merkle_root_at_detection: str | None = None


@dataclass
class VCPEvidenceBundle:
    """
    VCP evidence bundle for incident reporting.
    
    Provides cryptographic evidence of system state at incident time.
    """
    
    bundle_id: str
    incident_id: str
    created_at: datetime
    
    # Event references
    related_event_ids: list[str]
    
    # Merkle state at detection
    merkle_root: str | None
    merkle_tree_size: int | None
    anchor_timestamp: datetime | None
    anchor_type: str | None  # "TSA" or "BLOCKCHAIN"
    
    # Verification status
    all_events_verified: bool
    verification_score: float
    
    # Audit trail
    event_sequence_start: int | None = None
    event_sequence_end: int | None = None
    sequence_complete: bool = True


@dataclass
class DORAReportData:
    """
    DORA-compliant incident report data structure.
    
    Prepared data for submission to competent authorities.
    Note: Actual submission format may vary by NCA requirements.
    """
    
    report_id: str
    report_type: ReportType
    incident_id: str
    
    # Timing
    generated_at: datetime
    target_deadline: datetime
    
    # Classification
    classification: dict[str, Any]
    
    # Assessment
    assessment: dict[str, Any]
    
    # VCP evidence bundle
    vcp_evidence: VCPEvidenceBundle | None = None
    
    # Status
    is_within_deadline: bool = True
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = {
            "report_id": self.report_id,
            "report_type": self.report_type.value,
            "incident_id": self.incident_id,
            "generated_at": self.generated_at.isoformat(),
            "target_deadline": self.target_deadline.isoformat(),
            "classification": self.classification,
            "assessment": self.assessment,
            "is_within_deadline": self.is_within_deadline,
        }
        if self.vcp_evidence:
            data["vcp_evidence"] = {
                "bundle_id": self.vcp_evidence.bundle_id,
                "related_event_ids": self.vcp_evidence.related_event_ids,
                "merkle_root": self.vcp_evidence.merkle_root,
                "anchor_type": self.vcp_evidence.anchor_type,
                "all_events_verified": self.vcp_evidence.all_events_verified,
                "verification_score": self.vcp_evidence.verification_score,
            }
        return data


# ============================================================================
# DORA Reporter Support Tool
# ============================================================================

class DORAReportingSupport:
    """
    DORA incident reporting support tool.
    
    Provides data preparation and evidence bundling for DORA-compliant
    incident reports. This is a *support tool* - actual submissions
    must be prepared according to your NCA's specific requirements.
    
    Usage:
        support = DORAReportingSupport()
        
        # Prepare data for initial report
        report_data = support.prepare_initial_report(incident)
        
        # Bundle VCP evidence
        evidence = support.create_evidence_bundle(incident, verification_results)
        
        # Check deadlines
        deadlines = support.check_reporting_deadlines([incident1, incident2])
    """
    
    # Operational targets based on RTS/ITS (subject to regulatory updates)
    INITIAL_REPORT_TARGET_HOURS = 4
    INTERMEDIATE_REPORT_TARGET_HOURS = 72
    FINAL_REPORT_TARGET_DAYS = 30
    
    def __init__(
        self,
        initial_report_hours: int | None = None,
        intermediate_report_hours: int | None = None,
        final_report_days: int | None = None,
    ) -> None:
        """
        Initialize the DORA reporting support tool.
        
        Args:
            initial_report_hours: Hours for initial report target
            intermediate_report_hours: Hours for intermediate report target
            final_report_days: Days for final report target
        """
        self.initial_report_hours = (
            initial_report_hours or self.INITIAL_REPORT_TARGET_HOURS
        )
        self.intermediate_report_hours = (
            intermediate_report_hours or self.INTERMEDIATE_REPORT_TARGET_HOURS
        )
        self.final_report_days = (
            final_report_days or self.FINAL_REPORT_TARGET_DAYS
        )
        self._logger = logger.bind(component="DORAReportingSupport")
    
    def create_evidence_bundle(
        self,
        incident: IncidentRecord,
        verification_results: list[dict[str, Any]] | None = None,
    ) -> VCPEvidenceBundle:
        """
        Create a VCP evidence bundle for an incident.
        
        The evidence bundle provides cryptographic proof of the system
        state at the time of incident detection.
        
        Args:
            incident: The incident record
            verification_results: Optional list of VCP verification results
            
        Returns:
            VCPEvidenceBundle for inclusion in reports
        """
        bundle_id = f"VCP-EVIDENCE-{incident.incident_id}-{uuid4().hex[:8]}"
        
        # Calculate verification stats
        if verification_results:
            total = len(verification_results)
            passed = sum(1 for r in verification_results if r.get("status") == "PASSED")
            score = passed / total if total > 0 else 0.0
            all_verified = passed == total
        else:
            score = 0.0
            all_verified = False
        
        self._logger.info(
            "Creating VCP evidence bundle",
            bundle_id=bundle_id,
            incident_id=incident.incident_id,
            events_count=len(incident.related_vcp_events),
        )
        
        return VCPEvidenceBundle(
            bundle_id=bundle_id,
            incident_id=incident.incident_id,
            created_at=datetime.now(timezone.utc),
            related_event_ids=incident.related_vcp_events,
            merkle_root=incident.merkle_root_at_detection,
            merkle_tree_size=None,  # To be filled from anchor data
            anchor_timestamp=None,  # To be filled from anchor data
            anchor_type=None,       # To be filled from anchor data
            all_events_verified=all_verified,
            verification_score=score,
        )
    
    def prepare_initial_report(
        self,
        incident: IncidentRecord,
        classification_time: datetime | None = None,
        evidence_bundle: VCPEvidenceBundle | None = None,
    ) -> DORAReportData:
        """
        Prepare data for initial incident report.
        
        The initial report should be submitted within the target timeframe
        after the incident has been classified as major/significant.
        
        Args:
            incident: The incident record
            classification_time: When the incident was classified (default: now)
            evidence_bundle: Optional VCP evidence bundle
            
        Returns:
            DORAReportData ready for use in submission preparation
        """
        classification_time = classification_time or datetime.now(timezone.utc)
        deadline = classification_time + timedelta(hours=self.initial_report_hours)
        
        self._logger.info(
            "Preparing initial DORA report data",
            incident_id=incident.incident_id,
            classification_time=str(classification_time),
            deadline=str(deadline),
        )
        
        return DORAReportData(
            report_id=f"DORA-{incident.incident_id}-INIT-{uuid4().hex[:8]}",
            report_type=ReportType.INITIAL,
            incident_id=incident.incident_id,
            generated_at=datetime.now(timezone.utc),
            target_deadline=deadline,
            classification={
                "category": incident.category.value,
                "severity": incident.severity.value,
                "detected_at": incident.detected_at.isoformat(),
                "classified_at": classification_time.isoformat(),
            },
            assessment={
                "description": incident.description,
                "affected_services": incident.affected_services,
                "affected_clients": incident.affected_clients,
                "financial_impact_estimate": incident.financial_impact_estimate,
                "root_cause_known": incident.root_cause is not None,
            },
            vcp_evidence=evidence_bundle,
            is_within_deadline=datetime.now(timezone.utc) < deadline,
        )
    
    def prepare_intermediate_report(
        self,
        incident: IncidentRecord,
        previous_report: DORAReportData,
        updates: dict[str, Any],
        evidence_bundle: VCPEvidenceBundle | None = None,
    ) -> DORAReportData:
        """
        Prepare data for intermediate incident report.
        
        Intermediate reports provide updates on ongoing incidents.
        
        Args:
            incident: The incident record
            previous_report: Previous report in the chain
            updates: Dictionary of updates since last report
            evidence_bundle: Optional updated VCP evidence bundle
            
        Returns:
            DORAReportData for intermediate submission preparation
        """
        deadline = previous_report.generated_at + timedelta(
            hours=self.intermediate_report_hours
        )
        
        self._logger.info(
            "Preparing intermediate DORA report data",
            incident_id=incident.incident_id,
            previous_report=previous_report.report_id,
        )
        
        return DORAReportData(
            report_id=f"DORA-{incident.incident_id}-INT-{uuid4().hex[:8]}",
            report_type=ReportType.INTERMEDIATE,
            incident_id=incident.incident_id,
            generated_at=datetime.now(timezone.utc),
            target_deadline=deadline,
            classification={
                "category": incident.category.value,
                "severity": incident.severity.value,
                "status": "ONGOING" if not incident.resolved_at else "RESOLVED",
            },
            assessment={
                "updates": updates,
                "root_cause": incident.root_cause,
                "root_cause_identified_at": (
                    incident.root_cause_identified_at.isoformat()
                    if incident.root_cause_identified_at else None
                ),
                "resolution_actions": incident.resolution_actions,
            },
            vcp_evidence=evidence_bundle,
            is_within_deadline=datetime.now(timezone.utc) < deadline,
        )
    
    def prepare_final_report(
        self,
        incident: IncidentRecord,
        evidence_bundle: VCPEvidenceBundle | None = None,
    ) -> DORAReportData:
        """
        Prepare data for final incident report.
        
        The final report should be submitted after the incident is resolved.
        
        Args:
            incident: The incident record (must be resolved)
            evidence_bundle: Optional final VCP evidence bundle
            
        Returns:
            DORAReportData for final submission preparation
        """
        if not incident.resolved_at:
            raise ValueError("Cannot prepare final report for unresolved incident")
        
        deadline = incident.resolved_at + timedelta(days=self.final_report_days)
        
        self._logger.info(
            "Preparing final DORA report data",
            incident_id=incident.incident_id,
            resolved_at=str(incident.resolved_at),
        )
        
        return DORAReportData(
            report_id=f"DORA-{incident.incident_id}-FINAL-{uuid4().hex[:8]}",
            report_type=ReportType.FINAL,
            incident_id=incident.incident_id,
            generated_at=datetime.now(timezone.utc),
            target_deadline=deadline,
            classification={
                "category": incident.category.value,
                "severity": incident.severity.value,
                "status": "RESOLVED",
            },
            assessment={
                "description": incident.description,
                "root_cause": incident.root_cause,
                "total_duration_hours": (
                    incident.resolved_at - incident.detected_at
                ).total_seconds() / 3600,
                "affected_services": incident.affected_services,
                "affected_clients": incident.affected_clients,
                "financial_impact_actual": incident.financial_impact_estimate,
                "resolution_actions": incident.resolution_actions,
                "lessons_learned": [],  # To be filled by operator
            },
            vcp_evidence=evidence_bundle,
            is_within_deadline=datetime.now(timezone.utc) < deadline,
        )
    
    def check_reporting_deadlines(
        self,
        incidents: list[IncidentRecord],
    ) -> list[dict[str, Any]]:
        """
        Check reporting deadlines for a list of incidents.
        
        Args:
            incidents: List of incident records
            
        Returns:
            List of deadline status for each incident
        """
        results = []
        now = datetime.now(timezone.utc)
        
        for incident in incidents:
            status = {
                "incident_id": incident.incident_id,
                "severity": incident.severity.value,
                "detected_at": incident.detected_at.isoformat(),
                "is_resolved": incident.resolved_at is not None,
            }
            
            # Calculate initial report deadline
            initial_deadline = incident.detected_at + timedelta(
                hours=self.initial_report_hours
            )
            status["initial_report"] = {
                "deadline": initial_deadline.isoformat(),
                "overdue": now > initial_deadline,
                "hours_remaining": max(
                    0, (initial_deadline - now).total_seconds() / 3600
                ),
            }
            
            # Check if resolved
            if incident.resolved_at:
                final_deadline = incident.resolved_at + timedelta(
                    days=self.final_report_days
                )
                status["final_report"] = {
                    "deadline": final_deadline.isoformat(),
                    "overdue": now > final_deadline,
                    "days_remaining": max(
                        0, (final_deadline - now).total_seconds() / 86400
                    ),
                }
            
            results.append(status)
        
        return results


# Backward compatibility alias
DORAReporter = DORAReportingSupport
