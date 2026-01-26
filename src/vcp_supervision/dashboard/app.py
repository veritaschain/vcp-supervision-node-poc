"""
VCP Supervision Compliance Dashboard.

A web-based dashboard for visualizing verification results,
compliance scores, and alert management.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

import structlog

try:
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import HTMLResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.templating import Jinja2Templates
    import uvicorn
    DASHBOARD_AVAILABLE = True
except ImportError:
    DASHBOARD_AVAILABLE = False

if TYPE_CHECKING:
    from vcp_supervision.models import ComplianceReport, VerificationResult
    from vcp_supervision.node import SupervisionNode

logger = structlog.get_logger(__name__)


class ComplianceDashboard:
    """
    Web-based compliance dashboard for VCP Supervision Node.
    
    Provides real-time visualization of:
    - Verification results (pass/fail/warning)
    - Compliance scores by jurisdiction
    - Alert management
    - DORA reporting status
    
    Requires optional dependencies: pip install vcp-supervision[dashboard]
    """
    
    def __init__(
        self,
        node: "SupervisionNode" | None = None,
        host: str = "0.0.0.0",
        port: int = 8080,
        title: str = "VCP Supervision Dashboard",
    ) -> None:
        """
        Initialize the compliance dashboard.
        
        Args:
            node: SupervisionNode instance (optional)
            host: Host to bind to
            port: Port to listen on
            title: Dashboard title
        """
        if not DASHBOARD_AVAILABLE:
            raise ImportError(
                "Dashboard dependencies not installed. "
                "Install with: pip install vcp-supervision[dashboard]"
            )
        
        self.node = node
        self.host = host
        self.port = port
        self.title = title
        self._logger = logger.bind(component="ComplianceDashboard")
        
        # In-memory storage for results
        self._results: list[dict[str, Any]] = []
        self._alerts: list[dict[str, Any]] = []
        self._reports: list[dict[str, Any]] = []
        
        # Create FastAPI app
        self.app = self._create_app()
    
    def _create_app(self) -> FastAPI:
        """Create and configure the FastAPI application."""
        app = FastAPI(
            title=self.title,
            description="VCP Supervision Node Compliance Dashboard",
            version="0.1.0",
        )
        
        # Register routes
        self._register_routes(app)
        
        return app
    
    def _register_routes(self, app: FastAPI) -> None:
        """Register API routes."""
        
        @app.get("/", response_class=HTMLResponse)
        async def index() -> HTMLResponse:
            """Render the main dashboard page."""
            return HTMLResponse(content=self._render_dashboard())
        
        @app.get("/api/health")
        async def health() -> dict[str, Any]:
            """Health check endpoint."""
            return {
                "status": "healthy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "node_stats": self.node.get_stats() if self.node else None,
            }
        
        @app.get("/api/stats")
        async def stats() -> dict[str, Any]:
            """Get verification statistics."""
            if self.node:
                return self.node.get_stats()
            return self._compute_stats()
        
        @app.get("/api/results")
        async def results(
            limit: int = 100,
            status: str | None = None,
        ) -> list[dict[str, Any]]:
            """Get recent verification results."""
            filtered = self._results
            if status:
                filtered = [r for r in filtered if r.get("status") == status]
            return filtered[-limit:]
        
        @app.post("/api/results")
        async def add_result(request: Request) -> dict[str, Any]:
            """Add a new verification result."""
            data = await request.json()
            self._results.append({
                **data,
                "received_at": datetime.now(timezone.utc).isoformat(),
            })
            
            # Check for alerts
            if data.get("status") == "FAILED":
                self._add_alert(data)
            
            return {"status": "ok", "id": len(self._results)}
        
        @app.get("/api/alerts")
        async def alerts(
            limit: int = 50,
            acknowledged: bool | None = None,
        ) -> list[dict[str, Any]]:
            """Get alerts."""
            filtered = self._alerts
            if acknowledged is not None:
                filtered = [
                    a for a in filtered
                    if a.get("acknowledged") == acknowledged
                ]
            return filtered[-limit:]
        
        @app.post("/api/alerts/{alert_id}/acknowledge")
        async def acknowledge_alert(alert_id: int) -> dict[str, Any]:
            """Acknowledge an alert."""
            if alert_id < 0 or alert_id >= len(self._alerts):
                raise HTTPException(status_code=404, detail="Alert not found")
            
            self._alerts[alert_id]["acknowledged"] = True
            self._alerts[alert_id]["acknowledged_at"] = (
                datetime.now(timezone.utc).isoformat()
            )
            return {"status": "ok"}
        
        @app.get("/api/compliance/score")
        async def compliance_score(
            jurisdiction: str = "EU",
        ) -> dict[str, Any]:
            """Get compliance score for a jurisdiction."""
            return self._compute_compliance_score(jurisdiction)
        
        @app.get("/api/reports")
        async def reports(limit: int = 20) -> list[dict[str, Any]]:
            """Get generated compliance reports."""
            return self._reports[-limit:]
    
    def _add_alert(self, result: dict[str, Any]) -> None:
        """Add an alert from a failed verification result."""
        alert = {
            "id": len(self._alerts),
            "type": "VERIFICATION_FAILED",
            "severity": "HIGH",
            "error_code": result.get("error_code"),
            "message": result.get("message"),
            "event_id": result.get("event_id"),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "acknowledged": False,
        }
        self._alerts.append(alert)
        self._logger.warning("Alert created", alert_id=alert["id"])
    
    def _compute_stats(self) -> dict[str, Any]:
        """Compute statistics from stored results."""
        total = len(self._results)
        passed = sum(1 for r in self._results if r.get("status") == "PASSED")
        failed = sum(1 for r in self._results if r.get("status") == "FAILED")
        warning = sum(1 for r in self._results if r.get("status") == "WARNING")
        
        return {
            "events_verified": total,
            "events_passed": passed,
            "events_failed": failed,
            "events_warning": warning,
            "pass_rate": passed / total if total > 0 else 0.0,
            "active_alerts": sum(
                1 for a in self._alerts if not a.get("acknowledged")
            ),
        }
    
    def _compute_compliance_score(self, jurisdiction: str) -> dict[str, Any]:
        """Compute compliance score for a jurisdiction."""
        relevant = [
            r for r in self._results
            if r.get("jurisdiction") == jurisdiction
        ]
        
        if not relevant:
            return {
                "jurisdiction": jurisdiction,
                "score": None,
                "message": "No results for this jurisdiction",
            }
        
        avg_score = sum(
            r.get("compliance_score", 0) for r in relevant
        ) / len(relevant)
        
        return {
            "jurisdiction": jurisdiction,
            "score": round(avg_score, 3),
            "total_events": len(relevant),
            "integrity_score": self._compute_sub_score(relevant, "signature_valid"),
            "timing_score": self._compute_sub_score(relevant, "timing_valid"),
        }
    
    def _compute_sub_score(
        self,
        results: list[dict[str, Any]],
        field: str,
    ) -> float:
        """Compute sub-score for a specific field."""
        valid = sum(1 for r in results if r.get(field) is True)
        return round(valid / len(results), 3) if results else 0.0
    
    def _render_dashboard(self) -> str:
        """Render the dashboard HTML."""
        stats = self._compute_stats()
        
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.title}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/htmx.org@1.9.10"></script>
</head>
<body class="bg-gray-100 min-h-screen">
    <nav class="bg-indigo-600 text-white p-4">
        <div class="container mx-auto flex justify-between items-center">
            <h1 class="text-xl font-bold">VCP Supervision Dashboard</h1>
            <span class="text-sm">Verify, Don't Trust</span>
        </div>
    </nav>
    
    <main class="container mx-auto p-6">
        <!-- Stats Cards -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <div class="bg-white rounded-lg shadow p-6">
                <h3 class="text-gray-500 text-sm">Total Verified</h3>
                <p class="text-3xl font-bold text-gray-800">{stats['events_verified']}</p>
            </div>
            <div class="bg-white rounded-lg shadow p-6">
                <h3 class="text-gray-500 text-sm">Passed</h3>
                <p class="text-3xl font-bold text-green-600">{stats['events_passed']}</p>
            </div>
            <div class="bg-white rounded-lg shadow p-6">
                <h3 class="text-gray-500 text-sm">Failed</h3>
                <p class="text-3xl font-bold text-red-600">{stats['events_failed']}</p>
            </div>
            <div class="bg-white rounded-lg shadow p-6">
                <h3 class="text-gray-500 text-sm">Active Alerts</h3>
                <p class="text-3xl font-bold text-yellow-600">{stats['active_alerts']}</p>
            </div>
        </div>
        
        <!-- Pass Rate -->
        <div class="bg-white rounded-lg shadow p-6 mb-6">
            <h3 class="text-lg font-semibold mb-4">Compliance Score</h3>
            <div class="w-full bg-gray-200 rounded-full h-4">
                <div class="bg-green-600 h-4 rounded-full" 
                     style="width: {stats['pass_rate'] * 100:.1f}%"></div>
            </div>
            <p class="text-sm text-gray-600 mt-2">
                Pass Rate: {stats['pass_rate'] * 100:.1f}%
            </p>
        </div>
        
        <!-- Alerts Section -->
        <div class="bg-white rounded-lg shadow p-6 mb-6">
            <h3 class="text-lg font-semibold mb-4">Recent Alerts</h3>
            <div id="alerts" hx-get="/api/alerts?limit=5" hx-trigger="load, every 5s">
                <p class="text-gray-500">Loading alerts...</p>
            </div>
        </div>
        
        <!-- API Documentation Link -->
        <div class="text-center text-gray-500 text-sm">
            <p>API Documentation: <a href="/docs" class="text-indigo-600 hover:underline">/docs</a></p>
            <p class="mt-2">VeritasChain Standards Organization</p>
        </div>
    </main>
    
    <script>
        // Auto-refresh stats every 5 seconds
        setInterval(() => {{
            fetch('/api/stats')
                .then(r => r.json())
                .then(data => console.log('Stats updated:', data));
        }}, 5000);
    </script>
</body>
</html>
"""
    
    def add_result(self, result: "VerificationResult") -> None:
        """
        Add a verification result to the dashboard.
        
        Args:
            result: VerificationResult to add
        """
        self._results.append({
            "status": result.status.value,
            "error_code": result.error_code,
            "message": result.message,
            "compliance_score": result.compliance_score,
            "signature_valid": result.signature_valid,
            "merkle_valid": result.merkle_valid,
            "anchor_valid": result.anchor_valid,
            "timing_valid": result.timing_valid,
            "jurisdiction": result.jurisdiction,
            "elapsed_seconds": result.elapsed_seconds,
            "received_at": datetime.now(timezone.utc).isoformat(),
        })
        
        if result.status.value == "FAILED":
            self._add_alert({
                "status": result.status.value,
                "error_code": result.error_code,
                "message": result.message,
            })
    
    def add_report(self, report: "ComplianceReport") -> None:
        """
        Add a compliance report to the dashboard.
        
        Args:
            report: ComplianceReport to add
        """
        self._reports.append({
            "report_id": report.report_id,
            "generated_at": report.generated_at.isoformat(),
            "jurisdiction": report.jurisdiction,
            "total_events": report.total_events,
            "overall_score": report.overall_score,
            "pass_rate": report.pass_rate,
        })
    
    def run(self) -> None:
        """Run the dashboard server."""
        self._logger.info(
            "Starting dashboard",
            host=self.host,
            port=self.port,
        )
        uvicorn.run(self.app, host=self.host, port=self.port)
    
    async def run_async(self) -> None:
        """Run the dashboard server asynchronously."""
        config = uvicorn.Config(self.app, host=self.host, port=self.port)
        server = uvicorn.Server(config)
        await server.serve()
