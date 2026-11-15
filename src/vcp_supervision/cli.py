"""
VCP Supervision Node Command Line Interface.

Provides command-line tools for verification, reporting, and dashboard management.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from vcp_supervision import SupervisionNode, __version__
from vcp_supervision.models import (
    AnchorRecord,
    MerkleProof,
    VCPEvent,
    VerificationResult,
    VerificationStatus,
)

logger = structlog.get_logger(__name__)


def setup_logging(verbose: bool = False) -> None:
    """Configure structured logging."""
    level = logging.DEBUG if verbose else logging.INFO
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.dev.ConsoleRenderer() if sys.stderr.isatty()
            else structlog.processors.JSONRenderer(),
        ],
    )


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify VCP events from a file."""
    setup_logging(args.verbose)
    
    # Load configuration
    config_path = args.config if args.config else None
    node = SupervisionNode(config_path=config_path)
    
    try:
        # Load events
        with open(args.events) as f:
            data = json.load(f)
        
        events_data = data if isinstance(data, list) else [data]
        
        results = []
        for event_data in events_data:
            # Parse event
            event = VCPEvent(**event_data["event"])
            proof = MerkleProof(**event_data["proof"])
            anchor = AnchorRecord(**event_data["anchor"])
            
            # Verify
            result = node.verify_event(
                event=event,
                proof=proof,
                anchor=anchor,
                jurisdiction=args.jurisdiction,
                entity_type=args.entity_type,
            )
            
            # Retain the actual component verdicts and diagnostic context.
            # ``score`` remains an alias for consumers of older CLI output.
            results.append({
                **result.model_dump(mode="json"),
                "event_id": event.event_id,
                "score": result.compliance_score,
            })
            
            # Print result
            status_color = {
                "PASSED": "\033[92m",  # Green
                "FAILED": "\033[91m",  # Red
                "WARNING": "\033[93m",  # Yellow
            }.get(result.status.value, "")
            reset = "\033[0m"
            
            print(f"{status_color}[{result.status.value}]{reset} "
                  f"{event.event_id} - Score: {result.compliance_score:.3f}")
        
        # Summary
        total = len(results)
        passed = sum(1 for r in results if r["status"] == "PASSED")
        failed = sum(1 for r in results if r["status"] == "FAILED")
        unverified = total - passed - failed
        
        print(f"\n--- Summary ---")
        print(f"Total: {total}, Passed: {passed}, Failed: {failed}, Unverified: {unverified}")
        print(f"Pass Rate: {passed/total*100:.1f}%" if total > 0 else "N/A")
        
        # Output results if requested
        if args.output:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=2)
            print(f"\nResults written to {args.output}")
        
        if failed:
            return 1
        return 0 if total > 0 and passed == total else 2
        
    finally:
        node.close()


_COMPONENT_FIELDS = ("signature_valid", "merkle_valid", "anchor_valid", "timing_valid")


def _restore_result(record: Any) -> VerificationResult:
    """Restore saved results without promoting missing checks to success."""
    if not isinstance(record, dict):
        raise ValueError("Each saved result must be a JSON object")
    data = dict(record)
    if "compliance_score" not in data and "score" in data:
        data["compliance_score"] = data["score"]
    for field in _COMPONENT_FIELDS:
        value = data.get(field)
        if value is not None and type(value) is not bool:
            raise ValueError(f"{field} must be a boolean or null")
    result = VerificationResult.model_validate(data)
    if result.status == VerificationStatus.PASSED:
        components = [getattr(result, field) for field in _COMPONENT_FIELDS]
        if any(value is False for value in components):
            result.status = VerificationStatus.FAILED
            result.error_code = "RESULT_CHECKS_CONFLICT"
            result.message = "Saved PASSED status conflicts with a failed component check"
        elif any(value is None for value in components):
            result.status = VerificationStatus.INDETERMINATE
            result.error_code = "RESULT_CHECKS_INCOMPLETE"
            result.message = "Saved PASSED status lacks complete component results"
    return result


def cmd_report(args: argparse.Namespace) -> int:
    """Generate a compliance report."""
    setup_logging(args.verbose)
    
    node = SupervisionNode(config_path=args.config)
    
    try:
        # Load verification results
        with open(args.results) as f:
            results_data = json.load(f)
        
        if not isinstance(results_data, list):
            raise ValueError("Saved verification results must be a JSON array")
        results = [_restore_result(record) for record in results_data]
        
        # Generate report
        report = node.generate_compliance_report(
            results=results,
            jurisdiction=args.jurisdiction,
        )
        
        # Output report
        report_dict = {
            "report_id": report.report_id,
            "generated_at": report.generated_at.isoformat(),
            "jurisdiction": report.jurisdiction,
            "total_events": report.total_events,
            "passed_events": report.passed_events,
            "failed_events": report.failed_events,
            "warning_events": report.warning_events,
            "indeterminate_events": report.indeterminate_events,
            "overall_score": report.overall_score,
            "integrity_score": report.integrity_score,
            "completeness_score": report.completeness_score,
            "timing_score": report.timing_score,
            "pass_rate": report.pass_rate,
            "regulations_checked": report.regulations_checked,
            "issues": report.issues,
        }
        
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report_dict, f, indent=2)
            print(f"Report written to {args.output}")
        else:
            print(json.dumps(report_dict, indent=2))
        
        return 0
        
    finally:
        node.close()


def cmd_dashboard(args: argparse.Namespace) -> int:
    """Start the compliance dashboard."""
    setup_logging(args.verbose)
    
    try:
        from vcp_supervision.dashboard import ComplianceDashboard
    except ImportError:
        print("Dashboard dependencies not installed.")
        print("From the repository checkout, run: python -m pip install -e '.[dashboard]'")
        return 1
    
    node = SupervisionNode(config_path=args.config)
    dashboard = ComplianceDashboard(
        node=node,
        host=args.host,
        port=args.port,
    )
    
    print(f"Starting dashboard at http://{args.host}:{args.port}")
    dashboard.run()
    
    return 0


def cmd_timing_requirements(args: argparse.Namespace) -> int:
    """Display timing requirements for jurisdictions."""
    from vcp_supervision.verification.timing import TimingVerifier
    
    verifier = TimingVerifier()
    
    if args.jurisdiction:
        reqs = verifier.get_jurisdiction_requirements(args.jurisdiction)
        if not reqs:
            print(f"No requirements found for {args.jurisdiction}")
            return 1
        
        print(f"\nTiming Requirements for {args.jurisdiction}:")
        print("-" * 60)
        
        for entity_type, req in reqs.items():
            print(f"\n{entity_type}:")
            print(f"  Min Precision: {req.min_precision}")
            if req.max_utc_divergence_us:
                print(f"  Max UTC Divergence: {req.max_utc_divergence_us}µs")
            elif req.max_utc_divergence_ms:
                print(f"  Max UTC Divergence: {req.max_utc_divergence_ms}ms")
            print(f"  Traceability Required: {req.require_traceability}")
            print(f"  Annual Review: {req.annual_review_required}")
            print(f"  Evidence Grade: {req.evidence_grade}")
            print(f"  Reference: {req.regulation_reference}")
    else:
        # Show all jurisdictions
        all_reqs = verifier.get_all_requirements()
        
        print("\nTiming Requirements by Jurisdiction:")
        print("=" * 70)
        
        for jurisdiction, reqs in all_reqs.items():
            print(f"\n{jurisdiction}:")
            for entity_type, req in reqs.items():
                precision = (
                    f"{req.max_utc_divergence_us}µs"
                    if req.max_utc_divergence_us
                    else f"{req.max_utc_divergence_ms}ms"
                    if req.max_utc_divergence_ms
                    else "N/A"
                )
                print(f"  {entity_type}: {req.min_precision}, {precision}")
    
    return 0


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="vcp-supervision",
        description="VCP Supervision Node - Independent verification for regulatory authorities",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "-c", "--config",
        type=str,
        help="Path to configuration file",
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Verify command
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify VCP events",
    )
    verify_parser.add_argument(
        "events",
        type=str,
        help="Path to JSON file containing events to verify",
    )
    verify_parser.add_argument(
        "-j", "--jurisdiction",
        type=str,
        default="EU",
        help="Target jurisdiction (default: EU)",
    )
    verify_parser.add_argument(
        "-e", "--entity-type",
        type=str,
        default="NON_HFT",
        help="Entity type (default: NON_HFT)",
    )
    verify_parser.add_argument(
        "-o", "--output",
        type=str,
        help="Output file for results",
    )
    
    # Report command
    report_parser = subparsers.add_parser(
        "report",
        help="Generate compliance report",
    )
    report_parser.add_argument(
        "results",
        type=str,
        help="Path to JSON file containing verification results",
    )
    report_parser.add_argument(
        "-j", "--jurisdiction",
        type=str,
        default="EU",
        help="Target jurisdiction (default: EU)",
    )
    report_parser.add_argument(
        "-o", "--output",
        type=str,
        help="Output file for report",
    )
    
    # Dashboard command
    dashboard_parser = subparsers.add_parser(
        "dashboard",
        help="Start the compliance dashboard",
    )
    dashboard_parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0)",
    )
    dashboard_parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port to listen on (default: 8080)",
    )
    
    # Timing requirements command
    timing_parser = subparsers.add_parser(
        "timing",
        help="Display timing requirements",
    )
    timing_parser.add_argument(
        "-j", "--jurisdiction",
        type=str,
        help="Specific jurisdiction to display",
    )
    
    return parser


def main() -> int:
    """Main entry point for the CLI."""
    parser = create_parser()
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        return 0
    
    commands = {
        "verify": cmd_verify,
        "report": cmd_report,
        "dashboard": cmd_dashboard,
        "timing": cmd_timing_requirements,
    }
    
    handler = commands.get(args.command)
    if handler:
        return handler(args)
    
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
