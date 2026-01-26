"""
VCP Supervision Node API Routes.

Defines all REST API endpoints for verification, challenge, and reporting.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from uuid import uuid4

import structlog

try:
    from fastapi import APIRouter, Depends, HTTPException, Request, status
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field
    API_AVAILABLE = True
except ImportError:
    API_AVAILABLE = False
    # Stub for type checking
    class BaseModel:
        pass
    class Field:
        def __init__(self, *args, **kwargs):
            pass

if TYPE_CHECKING:
    from vcp_supervision.node import SupervisionNode

logger = structlog.get_logger(__name__)

# Create router
api_router = APIRouter() if API_AVAILABLE else None


# ============================================================================
# Request/Response Models
# ============================================================================

if API_AVAILABLE:
    
    class HealthResponse(BaseModel):
        """Health check response."""
        status: str = Field(description="Health status")
        timestamp: str = Field(description="Current timestamp")
        version: str = Field(description="API version")
        node_stats: dict[str, Any] | None = Field(default=None, description="Node statistics")
    
    
    class VerifyEventRequest(BaseModel):
        """Single event verification request."""
        event: dict[str, Any] = Field(description="VCP event data")
        proof: dict[str, Any] = Field(description="Merkle proof")
        anchor: dict[str, Any] = Field(description="Anchor record")
        jurisdiction: str = Field(default="EU", description="Target jurisdiction")
        entity_type: str = Field(default="NON_HFT", description="Entity type")
    
    
    class VerifyBatchRequest(BaseModel):
        """Batch verification request."""
        batch_id: str = Field(description="Batch identifier")
        events: list[dict[str, Any]] = Field(description="VCP events")
        proofs: list[dict[str, Any]] = Field(description="Merkle proofs")
        anchor: dict[str, Any] = Field(description="Shared anchor")
        jurisdiction: str = Field(default="EU", description="Target jurisdiction")
        entity_type: str = Field(default="NON_HFT", description="Entity type")
    
    
    class VerificationResponse(BaseModel):
        """Verification result response."""
        status: str = Field(description="Verification status (PASSED, FAILED, WARNING)")
        compliance_score: float = Field(description="Compliance score (0.0 to 1.0)")
        error_code: str | None = Field(default=None, description="Error code if failed")
        message: str | None = Field(default=None, description="Human-readable message")
        signature_valid: bool = Field(description="Signature verification result")
        merkle_valid: bool = Field(description="Merkle proof verification result")
        anchor_valid: bool = Field(description="Anchor verification result")
        timing_valid: bool = Field(description="Timing requirements result")
        elapsed_seconds: float = Field(description="Verification duration")
    
    
    class ChallengeRequest(BaseModel):
        """On-demand proof challenge request."""
        challenge_id: str = Field(default_factory=lambda: str(uuid4()))
        challenge_type: str = Field(description="Challenge type")
        target_entity_id: str = Field(description="Target entity ID")
        event_id: str | None = Field(default=None, description="Specific event ID")
        sequence_start: int | None = Field(default=None, description="Sequence range start")
        sequence_end: int | None = Field(default=None, description="Sequence range end")
        time_start: str | None = Field(default=None, description="Time window start")
        time_end: str | None = Field(default=None, description="Time window end")
        algorithm_id: str | None = Field(default=None, description="Algorithm ID for audit")
        response_deadline: str | None = Field(default=None, description="Response deadline")
    
    
    class ChallengeResponse(BaseModel):
        """Challenge response (from firm)."""
        response_id: str = Field(description="Response identifier")
        challenge_id: str = Field(description="Original challenge ID")
        status: str = Field(description="Response status")
        events: list[dict[str, Any]] = Field(default=[], description="Requested events")
        proofs: list[dict[str, Any]] = Field(default=[], description="Merkle proofs")
        anchors: list[dict[str, Any]] = Field(default=[], description="Anchor records")
    
    
    class ChallengeVerificationResult(BaseModel):
        """Result of verifying a challenge response."""
        challenge_id: str
        verification_status: str
        events_verified: int
        events_passed: int
        events_failed: int
        completeness_verified: bool
        overall_score: float
        details: list[dict[str, Any]]
    
    
    class ComplianceReportRequest(BaseModel):
        """Compliance report generation request."""
        report_type: str = Field(default="SUMMARY", description="Report type")
        jurisdiction: str = Field(default="EU", description="Target jurisdiction")
        entity_id: str | None = Field(default=None, description="Filter by entity")
        start_date: str | None = Field(default=None, description="Report period start")
        end_date: str | None = Field(default=None, description="Report period end")


# ============================================================================
# Dependency Injection
# ============================================================================

def get_node(request: Request) -> "SupervisionNode":
    """Get the SupervisionNode from app state."""
    node = request.app.state.node
    if node is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Supervision node not initialized",
        )
    return node


# ============================================================================
# Health Endpoints
# ============================================================================

if API_AVAILABLE:
    
    @api_router.get(
        "/health",
        response_model=HealthResponse,
        tags=["health"],
        summary="Health check",
        description="Check API health and get basic statistics",
    )
    async def health_check(request: Request) -> HealthResponse:
        """Health check endpoint."""
        node = request.app.state.node
        stats = node.get_stats() if node else None
        
        return HealthResponse(
            status="healthy",
            timestamp=datetime.now(timezone.utc).isoformat(),
            version="0.1.0",
            node_stats=stats,
        )
    
    
    @api_router.get(
        "/ready",
        tags=["health"],
        summary="Readiness check",
        description="Check if the service is ready to accept requests",
    )
    async def readiness_check(request: Request) -> dict[str, Any]:
        """Readiness check for Kubernetes/load balancers."""
        node = request.app.state.node
        if node is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Node not ready",
            )
        return {"ready": True}


# ============================================================================
# Verification Endpoints
# ============================================================================

if API_AVAILABLE:
    
    @api_router.post(
        "/verify/event",
        response_model=VerificationResponse,
        tags=["verification"],
        summary="Verify single event",
        description="Verify a single VCP event with its Merkle proof and anchor",
    )
    async def verify_event(
        request: VerifyEventRequest,
        node: "SupervisionNode" = Depends(get_node),
    ) -> VerificationResponse:
        """Verify a single VCP event."""
        from vcp_supervision.models import (
            AnchorRecord,
            MerkleProof,
            VCPEvent,
        )
        
        try:
            # Parse input
            event = VCPEvent(**request.event)
            proof = MerkleProof(**request.proof)
            anchor = AnchorRecord(**request.anchor)
            
            # Verify
            result = node.verify_event(
                event=event,
                proof=proof,
                anchor=anchor,
                jurisdiction=request.jurisdiction,
                entity_type=request.entity_type,
            )
            
            return VerificationResponse(
                status=result.status.value,
                compliance_score=result.compliance_score,
                error_code=result.error_code,
                message=result.message,
                signature_valid=result.signature_valid,
                merkle_valid=result.merkle_valid,
                anchor_valid=result.anchor_valid,
                timing_valid=result.timing_valid,
                elapsed_seconds=result.elapsed_seconds,
            )
            
        except Exception as e:
            logger.exception("Verification error", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Verification failed: {str(e)}",
            )
    
    
    @api_router.post(
        "/verify/batch",
        tags=["verification"],
        summary="Verify event batch",
        description="Verify a batch of VCP events with completeness checking",
    )
    async def verify_batch(
        request: VerifyBatchRequest,
        node: "SupervisionNode" = Depends(get_node),
    ) -> dict[str, Any]:
        """Verify a batch of VCP events."""
        from vcp_supervision.models import (
            AnchorRecord,
            MerkleProof,
            VCPEvent,
        )
        
        try:
            # Parse inputs
            events = [VCPEvent(**e) for e in request.events]
            proofs = [MerkleProof(**p) for p in request.proofs]
            anchor = AnchorRecord(**request.anchor)
            
            # Verify batch
            results = node.verify_batch(
                events=events,
                proofs=proofs,
                anchor=anchor,
                jurisdiction=request.jurisdiction,
                entity_type=request.entity_type,
            )
            
            # Aggregate results
            total = len(results)
            passed = sum(1 for r in results if r.status.value == "PASSED")
            failed = sum(1 for r in results if r.status.value == "FAILED")
            warning = sum(1 for r in results if r.status.value == "WARNING")
            
            return {
                "batch_id": request.batch_id,
                "total_events": total,
                "passed": passed,
                "failed": failed,
                "warning": warning,
                "pass_rate": passed / total if total > 0 else 0.0,
                "results": [
                    {
                        "event_id": events[i].event_id,
                        "status": results[i].status.value,
                        "score": results[i].compliance_score,
                        "error_code": results[i].error_code,
                    }
                    for i in range(len(results))
                ],
            }
            
        except Exception as e:
            logger.exception("Batch verification error", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Batch verification failed: {str(e)}",
            )


# ============================================================================
# Challenge Endpoints (Assertion C)
# ============================================================================

if API_AVAILABLE:
    
    @api_router.post(
        "/challenge/create",
        tags=["challenge"],
        summary="Create challenge request",
        description="Create an on-demand proof request for a regulated entity",
    )
    async def create_challenge(
        request: ChallengeRequest,
        node: "SupervisionNode" = Depends(get_node),
    ) -> dict[str, Any]:
        """Create a challenge request."""
        challenge_id = request.challenge_id
        
        # Store challenge (in production, this would go to a database)
        # For PoC, we just return the challenge details
        
        return {
            "challenge_id": challenge_id,
            "status": "PENDING",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "challenge_type": request.challenge_type,
            "target_entity_id": request.target_entity_id,
            "response_deadline": request.response_deadline,
            "message": "Challenge created. Awaiting response from target entity.",
        }
    
    
    @api_router.post(
        "/challenge/{challenge_id}/response",
        tags=["challenge"],
        summary="Submit challenge response",
        description="Submit a response to an on-demand proof challenge",
    )
    async def submit_challenge_response(
        challenge_id: str,
        response: ChallengeResponse,
        node: "SupervisionNode" = Depends(get_node),
    ) -> ChallengeVerificationResult:
        """Submit and verify a challenge response."""
        from vcp_supervision.models import (
            AnchorRecord,
            MerkleProof,
            VCPEvent,
        )
        
        if response.challenge_id != challenge_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Challenge ID mismatch",
            )
        
        try:
            # Parse and verify each event
            results = []
            for i, event_data in enumerate(response.events):
                event = VCPEvent(**event_data)
                proof = MerkleProof(**response.proofs[i])
                
                # Find matching anchor
                anchor_data = response.anchors[0] if response.anchors else None
                if anchor_data is None:
                    raise ValueError("No anchor provided")
                anchor = AnchorRecord(**anchor_data)
                
                # Verify
                result = node.verify_event(
                    event=event,
                    proof=proof,
                    anchor=anchor,
                )
                
                results.append({
                    "event_id": event.event_id,
                    "status": result.status.value,
                    "score": result.compliance_score,
                    "error_code": result.error_code,
                })
            
            # Calculate totals
            total = len(results)
            passed = sum(1 for r in results if r["status"] == "PASSED")
            failed = sum(1 for r in results if r["status"] == "FAILED")
            
            return ChallengeVerificationResult(
                challenge_id=challenge_id,
                verification_status="COMPLETE",
                events_verified=total,
                events_passed=passed,
                events_failed=failed,
                completeness_verified=True,  # Would check sequence gaps in production
                overall_score=passed / total if total > 0 else 0.0,
                details=results,
            )
            
        except Exception as e:
            logger.exception("Challenge verification error", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Challenge verification failed: {str(e)}",
            )
    
    
    @api_router.get(
        "/challenge/{challenge_id}",
        tags=["challenge"],
        summary="Get challenge status",
        description="Get the current status of a challenge request",
    )
    async def get_challenge_status(
        challenge_id: str,
        node: "SupervisionNode" = Depends(get_node),
    ) -> dict[str, Any]:
        """Get challenge status."""
        # In production, this would look up from database
        return {
            "challenge_id": challenge_id,
            "status": "PENDING",
            "message": "Challenge status lookup not implemented in PoC",
        }


# ============================================================================
# Report Endpoints
# ============================================================================

if API_AVAILABLE:
    
    @api_router.post(
        "/reports/compliance",
        tags=["reports"],
        summary="Generate compliance report",
        description="Generate a compliance report for a jurisdiction or entity",
    )
    async def generate_compliance_report(
        request: ComplianceReportRequest,
        node: "SupervisionNode" = Depends(get_node),
    ) -> dict[str, Any]:
        """Generate a compliance report."""
        # In production, this would aggregate verification results
        return {
            "report_id": str(uuid4()),
            "report_type": request.report_type,
            "jurisdiction": request.jurisdiction,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "status": "Report generation not fully implemented in PoC",
            "summary": {
                "total_events": 0,
                "passed": 0,
                "failed": 0,
                "compliance_score": 0.0,
            },
        }
    
    
    @api_router.get(
        "/reports/{report_id}",
        tags=["reports"],
        summary="Get report",
        description="Retrieve a previously generated compliance report",
    )
    async def get_report(
        report_id: str,
        node: "SupervisionNode" = Depends(get_node),
    ) -> dict[str, Any]:
        """Get a compliance report by ID."""
        return {
            "report_id": report_id,
            "status": "Report retrieval not implemented in PoC",
        }


# ============================================================================
# Admin Endpoints
# ============================================================================

if API_AVAILABLE:
    
    @api_router.get(
        "/admin/stats",
        tags=["admin"],
        summary="Get statistics",
        description="Get detailed verification statistics",
    )
    async def get_stats(
        node: "SupervisionNode" = Depends(get_node),
    ) -> dict[str, Any]:
        """Get node statistics."""
        return node.get_stats()
    
    
    @api_router.get(
        "/admin/config",
        tags=["admin"],
        summary="Get configuration",
        description="Get current node configuration (sanitized)",
    )
    async def get_config(
        node: "SupervisionNode" = Depends(get_node),
    ) -> dict[str, Any]:
        """Get sanitized configuration."""
        config = node.config.copy()
        # Remove sensitive values
        if "api_keys" in config:
            config["api_keys"] = "[REDACTED]"
        return config
    
    
    @api_router.get(
        "/admin/jurisdictions",
        tags=["admin"],
        summary="List jurisdictions",
        description="List supported jurisdictions and their timing requirements",
    )
    async def list_jurisdictions(
        node: "SupervisionNode" = Depends(get_node),
    ) -> dict[str, Any]:
        """List supported jurisdictions."""
        requirements = node.engine.timing_verifier.get_all_requirements()
        
        jurisdictions = {}
        for jurisdiction, reqs in requirements.items():
            jurisdictions[jurisdiction] = {
                entity_type: {
                    "min_precision": req.min_precision,
                    "max_divergence_us": req.max_utc_divergence_us,
                    "max_divergence_ms": req.max_utc_divergence_ms,
                    "regulation": req.regulation_reference,
                }
                for entity_type, req in reqs.items()
            }
        
        return {
            "supported_jurisdictions": list(requirements.keys()),
            "requirements": jurisdictions,
        }
