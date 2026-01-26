"""
VCP Supervision Node API Server.

FastAPI-based server for the VCP Supervision Node REST API.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

import structlog

try:
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    import uvicorn
    API_AVAILABLE = True
except ImportError:
    API_AVAILABLE = False

if TYPE_CHECKING:
    from vcp_supervision.node import SupervisionNode

logger = structlog.get_logger(__name__)


def create_app(
    node: "SupervisionNode | None" = None,
    title: str = "VCP Supervision Node API",
    description: str = "Independent verification infrastructure for VCP-compliant trading logs",
    version: str = "0.1.0",
    cors_origins: list[str] | None = None,
) -> "FastAPI":
    """
    Create and configure the FastAPI application.
    
    Args:
        node: SupervisionNode instance (optional, can be set later)
        title: API title
        description: API description
        version: API version
        cors_origins: Allowed CORS origins (None = no CORS)
    
    Returns:
        Configured FastAPI application
    """
    if not API_AVAILABLE:
        raise ImportError(
            "API dependencies not installed. "
            "Install with: pip install vcp-supervision[api]"
        )
    
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Application lifespan handler."""
        logger.info("Starting VCP Supervision API")
        yield
        logger.info("Shutting down VCP Supervision API")
        if app.state.node:
            app.state.node.close()
    
    app = FastAPI(
        title=title,
        description=description,
        version=version,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        openapi_tags=[
            {
                "name": "health",
                "description": "Health check and status endpoints",
            },
            {
                "name": "verification",
                "description": "Batch and event verification endpoints",
            },
            {
                "name": "challenge",
                "description": "On-demand proof request/response (Assertion C)",
            },
            {
                "name": "reports",
                "description": "Compliance report generation",
            },
            {
                "name": "admin",
                "description": "Administrative operations",
            },
        ],
    )
    
    # Store node in app state
    app.state.node = node
    
    # Configure CORS if origins provided
    if cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    
    # Register routes
    from vcp_supervision.api.routes import api_router
    app.include_router(api_router)
    
    # Exception handlers
    @app.exception_handler(ValueError)
    async def value_error_handler(request, exc):
        return JSONResponse(
            status_code=400,
            content={"error": "validation_error", "detail": str(exc)},
        )
    
    @app.exception_handler(Exception)
    async def general_exception_handler(request, exc):
        logger.exception("Unhandled exception", error=str(exc))
        return JSONResponse(
            status_code=500,
            content={"error": "internal_error", "detail": "An internal error occurred"},
        )
    
    return app


def run_server(
    node: "SupervisionNode | None" = None,
    host: str = "0.0.0.0",
    port: int = 8080,
    reload: bool = False,
    workers: int = 1,
    cors_origins: list[str] | None = None,
) -> None:
    """
    Run the API server.
    
    Args:
        node: SupervisionNode instance
        host: Host to bind to
        port: Port to listen on
        reload: Enable auto-reload (development only)
        workers: Number of worker processes
        cors_origins: Allowed CORS origins
    """
    if not API_AVAILABLE:
        raise ImportError(
            "API dependencies not installed. "
            "Install with: pip install vcp-supervision[api]"
        )
    
    app = create_app(node=node, cors_origins=cors_origins)
    
    logger.info(
        "Starting API server",
        host=host,
        port=port,
        workers=workers,
    )
    
    uvicorn.run(
        app,
        host=host,
        port=port,
        reload=reload,
        workers=workers,
    )


async def run_server_async(
    node: "SupervisionNode | None" = None,
    host: str = "0.0.0.0",
    port: int = 8080,
    cors_origins: list[str] | None = None,
) -> None:
    """
    Run the API server asynchronously.
    
    Args:
        node: SupervisionNode instance
        host: Host to bind to
        port: Port to listen on
        cors_origins: Allowed CORS origins
    """
    if not API_AVAILABLE:
        raise ImportError(
            "API dependencies not installed. "
            "Install with: pip install vcp-supervision[api]"
        )
    
    app = create_app(node=node, cors_origins=cors_origins)
    
    config = uvicorn.Config(app, host=host, port=port)
    server = uvicorn.Server(config)
    await server.serve()
