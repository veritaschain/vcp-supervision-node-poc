"""
Incident Reporting Support Tools.

This module provides support tools for regulatory incident reporting,
including data preparation, evidence bundling, and deadline tracking.

IMPORTANT: These are *support tools* - they do NOT generate actual
regulatory submissions. Final submissions must be prepared according
to your competent authority's specific requirements.

Currently supported frameworks:
- DORA (EU Digital Operational Resilience Act)

Planned support:
- FCA incident reporting
- SEC Form BD amendment reporting
- MAS incident notification
"""

from vcp_supervision.reporting.incident.dora import (
    DORAReportData,
    DORAReporter,
    DORAReportingSupport,
    IncidentCategory,
    IncidentRecord,
    IncidentSeverity,
    ReportType,
    VCPEvidenceBundle,
)

__all__ = [
    "DORAReportData",
    "DORAReporter",
    "DORAReportingSupport",
    "IncidentCategory",
    "IncidentRecord",
    "IncidentSeverity",
    "ReportType",
    "VCPEvidenceBundle",
]
