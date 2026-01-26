"""
VCP Supervision Node - Independent verification infrastructure for regulatory authorities.

This package provides tools for regulatory authorities to independently verify
the integrity, completeness, and temporal compliance of VCP-compliant
algorithmic trading audit trails.

Core Principle: "Verify, Don't Trust"
"""

from vcp_supervision.node import SupervisionNode
from vcp_supervision.verification import VerificationEngine, VerificationResult
from vcp_supervision.models import VCPEvent, MerkleProof, AnchorRecord

__version__ = "0.1.0"
__author__ = "VeritasChain Standards Organization"
__email__ = "info@veritaschain.org"

__all__ = [
    "SupervisionNode",
    "VerificationEngine",
    "VerificationResult",
    "VCPEvent",
    "MerkleProof",
    "AnchorRecord",
    "__version__",
]
