"""
Reporting Support Module.

Provides support tools for regulatory reporting requirements.

IMPORTANT: These are *support tools* - they do NOT generate actual
regulatory submissions. Final submissions must be prepared according
to your competent authority's specific requirements.

Submodules:
- incident/: Incident reporting support (DORA, etc.)

Usage:
    from vcp_supervision.reporting.incident import (
        DORAReportingSupport,
        IncidentRecord,
        VCPEvidenceBundle,
    )
    
    support = DORAReportingSupport()
    evidence = support.create_evidence_bundle(incident)
    report_data = support.prepare_initial_report(incident, evidence_bundle=evidence)
"""

# Re-export commonly used classes for convenience
from vcp_supervision.reporting.incident import (
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
