"""
External anchor verification module.

Implements verification of RFC 3161 Timestamp Authority (TSA) tokens
and blockchain anchors to prove the existence and timing of Merkle roots.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import httpx
import structlog

if TYPE_CHECKING:
    from vcp_supervision.models import AnchorRecord, AnchorType

logger = structlog.get_logger(__name__)


class AnchorVerificationError(Exception):
    """Raised when anchor verification fails."""
    
    def __init__(self, error_code: str, message: str) -> None:
        self.error_code = error_code
        self.message = message
        super().__init__(message)


class AnchorVerifier:
    """
    External anchor verifier for TSA and blockchain anchors.
    
    Verifies that Merkle roots have been properly anchored to external
    time sources, providing independent proof of existence and timing.
    
    Regulatory Alignment:
    - eIDAS Article 42: Qualified electronic timestamps
    - SEC Rule 17a-4: Immutable records
    - DORA: External validation requirements
    
    Technical Standards:
    - RFC 3161: Time-Stamp Protocol (TSP)
    - RFC 5816: ESSCertIDv2 for TSA certificates
    """
    
    # List of trusted eIDAS qualified TSA providers (subset for PoC)
    EIDAS_QUALIFIED_TSAS = {
        "https://freetsa.org/tsr",
        "https://timestamp.digicert.com",
        "https://timestamp.sectigo.com",
        # Add more qualified TSAs as needed
    }
    
    def __init__(
        self,
        trusted_tsa_urls: set[str] | None = None,
        verify_blockchain: bool = True,
        blockchain_rpc_urls: dict[str, str] | None = None,
    ) -> None:
        """
        Initialize the anchor verifier.
        
        Args:
            trusted_tsa_urls: Set of trusted TSA URLs
            verify_blockchain: Whether to verify blockchain anchors online
            blockchain_rpc_urls: Mapping of chain name to RPC URL
        """
        self.trusted_tsa_urls = trusted_tsa_urls or self.EIDAS_QUALIFIED_TSAS
        self.verify_blockchain = verify_blockchain
        self.blockchain_rpc_urls = blockchain_rpc_urls or {}
        self._logger = logger.bind(component="AnchorVerifier")
        self._http_client = httpx.Client(timeout=30.0)
    
    def verify(
        self,
        merkle_root: bytes | str,
        anchor: AnchorRecord,
    ) -> dict[str, any]:
        """
        Verify an external anchor record.
        
        Args:
            merkle_root: The Merkle root that was anchored
            anchor: The anchor record to verify
            
        Returns:
            Verification result dictionary
        """
        if isinstance(merkle_root, str):
            merkle_root = base64.b64decode(merkle_root)
        
        self._logger.debug(
            "Verifying anchor",
            anchor_type=anchor.anchor_type.value,
            anchor_timestamp=str(anchor.anchor_timestamp),
        )
        
        results = {
            "tsa": None,
            "blockchain": None,
        }
        
        # Verify TSA anchor if present
        if anchor.tsa_anchor:
            results["tsa"] = self._verify_tsa_anchor(merkle_root, anchor)
        
        # Verify blockchain anchor if present
        if anchor.blockchain_anchor:
            results["blockchain"] = self._verify_blockchain_anchor(merkle_root, anchor)
        
        # Aggregate results
        return self._aggregate_results(anchor, results)
    
    def _verify_tsa_anchor(
        self,
        merkle_root: bytes,
        anchor: AnchorRecord,
    ) -> dict[str, any]:
        """
        Verify an RFC 3161 TSA anchor.
        
        Args:
            merkle_root: The Merkle root that was timestamped
            anchor: The anchor record containing TSA details
            
        Returns:
            TSA verification result
        """
        tsa = anchor.tsa_anchor
        self._logger.debug("Verifying TSA anchor", tsa_url=tsa.tsa_url)
        
        try:
            # RFC 3161 token parsing, message-imprint matching, signature
            # and TSA trust-chain validation are not implemented in this PoC.
            # Decoding base64 or matching a URL is not verification.
            return {
                "status": "FAILED",
                "error_code": "TSA_VERIFICATION_NOT_IMPLEMENTED",
                "message": "RFC 3161 TSA verification is not implemented; proof not accepted",
                "is_eidas_qualified": False,
                "legal_presumption": False,
            }

        except ValueError as e:
            self._logger.error("Invalid TSA token", error=str(e))
            return {
                "status": "FAILED",
                "error_code": "TSA_TOKEN_INVALID",
                "message": f"Invalid TSA token format: {e}",
            }
        except Exception as e:
            self._logger.exception("TSA verification error")
            return {
                "status": "FAILED",
                "error_code": "TSA_VERIFICATION_ERROR",
                "message": f"TSA verification failed: {e}",
            }
    
    def _verify_blockchain_anchor(
        self,
        merkle_root: bytes,
        anchor: AnchorRecord,
    ) -> dict[str, any]:
        """
        Verify a blockchain anchor.
        
        Args:
            merkle_root: The Merkle root that was anchored
            anchor: The anchor record containing blockchain details
            
        Returns:
            Blockchain verification result
        """
        bc = anchor.blockchain_anchor
        self._logger.debug(
            "Verifying blockchain anchor",
            chain=bc.chain,
            network=bc.network,
            tx_hash=bc.transaction_hash,
        )
        
        try:
            # Step 1: Verify the Merkle root in the anchor matches
            anchor_root = base64.b64decode(bc.merkle_root_in_tx) if isinstance(
                bc.merkle_root_in_tx, str
            ) else bc.merkle_root_in_tx
            
            if merkle_root != anchor_root:
                return {
                    "status": "FAILED",
                    "error_code": "BC_ROOT_MISMATCH",
                    "message": "Merkle root does not match blockchain anchor",
                }
            
            # Caller-supplied roots and confirmation counts are not an
            # authenticated chain commitment. The RPC helper also lacks payload,
            # canonical-chain and finality validation, so do not accept either path.
            return {
                "status": "FAILED",
                "error_code": "BC_VERIFICATION_NOT_IMPLEMENTED",
                "message": "Blockchain commitment and finality verification are not implemented; proof not accepted",
            }

        except Exception as e:
            self._logger.exception("Blockchain verification error")
            return {
                "status": "FAILED",
                "error_code": "BC_VERIFICATION_ERROR",
                "message": f"Blockchain verification failed: {e}",
            }
    
    def _verify_blockchain_online(
        self,
        bc_anchor: "BlockchainAnchor",
    ) -> dict[str, any]:
        """
        Verify blockchain anchor by querying the chain directly.
        
        Args:
            bc_anchor: Blockchain anchor details
            
        Returns:
            Online verification result
        """
        rpc_url = self.blockchain_rpc_urls.get(bc_anchor.chain)
        if not rpc_url:
            return {
                "status": "WARNING",
                "error_code": "BC_NO_RPC",
                "message": f"No RPC URL configured for {bc_anchor.chain}",
            }
        
        try:
            # Query transaction
            response = self._http_client.post(
                rpc_url,
                json={
                    "jsonrpc": "2.0",
                    "method": "eth_getTransactionByHash",
                    "params": [bc_anchor.transaction_hash],
                    "id": 1,
                },
            )
            response.raise_for_status()
            
            result = response.json().get("result")
            if not result:
                return {
                    "status": "FAILED",
                    "error_code": "BC_TX_NOT_FOUND",
                    "message": f"Transaction {bc_anchor.transaction_hash} not found",
                }
            
            return {
                "status": "FAILED",
                "error_code": "BC_COMMITMENT_NOT_VERIFIED",
                "message": "Transaction existence does not prove its Merkle commitment or finality",
            }

        except httpx.HTTPError as e:
            self._logger.warning("RPC request failed", error=str(e))
            return {
                "status": "WARNING",
                "error_code": "BC_RPC_ERROR",
                "message": f"Could not verify on-chain: {e}",
            }
    
    def _get_min_confirmations(self, chain: str) -> int:
        """Get minimum confirmations required for finality."""
        # Minimum confirmations for different chains
        confirmations = {
            "ethereum": 12,
            "polygon": 128,
            "arbitrum": 1,
            "optimism": 1,
        }
        return confirmations.get(chain.lower(), 6)
    
    def _aggregate_results(
        self,
        anchor: AnchorRecord,
        results: dict[str, dict | None],
    ) -> dict[str, any]:
        """
        Aggregate TSA and blockchain verification results.
        
        Args:
            anchor: The anchor record
            results: Individual verification results
            
        Returns:
            Aggregated verification result
        """
        tsa_result = results.get("tsa")
        bc_result = results.get("blockchain")
        
        # Determine overall status
        statuses = []
        if tsa_result:
            statuses.append(tsa_result["status"])
        if bc_result:
            statuses.append(bc_result["status"])
        
        if not statuses:
            return {
                "status": "FAILED",
                "error_code": "NO_ANCHOR",
                "message": "No anchor data to verify",
            }
        
        # FAILED > WARNING > PASSED
        if any(status not in ("PASSED", "WARNING") for status in statuses):
            overall_status = "FAILED"
        elif "WARNING" in statuses:
            overall_status = "WARNING"
        else:
            overall_status = "PASSED"
        
        return {
            "status": overall_status,
            "anchor_type": anchor.anchor_type.value,
            "anchor_timestamp": str(anchor.anchor_timestamp),
            "tsa_result": tsa_result,
            "blockchain_result": bc_result,
            "is_dual_anchored": tsa_result is not None and bc_result is not None,
            "has_legal_presumption": (
                tsa_result is not None
                and tsa_result.get("status") == "PASSED"
                and tsa_result.get("legal_presumption", False)
            ),
        }
    
    def close(self) -> None:
        """Close the HTTP client."""
        self._http_client.close()
    
    def __enter__(self) -> "AnchorVerifier":
        return self
    
    def __exit__(self, *args: any) -> None:
        self.close()
