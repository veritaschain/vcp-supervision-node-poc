"""
VCP Supervision Node REST API Module.

Provides FastAPI-based REST endpoints for:
- Batch submission and verification
- Challenge request/response handling
- Compliance report generation
- Real-time status monitoring
"""

from vcp_supervision.api.server import create_app
from vcp_supervision.api.routes import api_router

__all__ = ["create_app", "api_router"]
