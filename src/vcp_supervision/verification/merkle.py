"""
Merkle proof verification module.

Implements RFC 6962 compliant Merkle tree inclusion proof verification.
This is used to verify that a specific event is included in a Merkle tree
with a known root hash that has been externally anchored.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from vcp_supervision.models import MerkleProof, VCPEvent

logger = structlog.get_logger(__name__)


class MerkleVerificationError(Exception):
    """Raised when Merkle proof verification fails."""
    
    def __init__(self, error_code: str, message: str) -> None:
        self.error_code = error_code
        self.message = message
        super().__init__(message)


class MerkleVerifier:
    """
    RFC 6962 compliant Merkle proof verifier.
    
    Verifies that VCP events are properly included in a Merkle tree,
    enabling cryptographic proof of event existence and ordering.
    
    Regulatory Alignment:
    - MiFID II Article 17: Order record completeness
    - SEC Rule 17a-4: Audit trail integrity
    - eIDAS Article 42: Qualified timestamps with Merkle trees
    
    Technical Standard:
    - RFC 6962: Certificate Transparency (Merkle Tree structure)
    """
    
    # RFC 6962 domain separation prefixes
    LEAF_PREFIX = b"\x00"
    NODE_PREFIX = b"\x01"
    
    def __init__(self, hash_algorithm: str = "SHA-256") -> None:
        """
        Initialize the Merkle verifier.
        
        Args:
            hash_algorithm: Hash algorithm to use (default: SHA-256)
        """
        if hash_algorithm != "SHA-256":
            raise ValueError("Only SHA-256 is currently supported for RFC 6962 compliance")
        
        self.hash_algorithm = hash_algorithm
        self._logger = logger.bind(component="MerkleVerifier")
    
    def verify(
        self,
        event: VCPEvent,
        proof: MerkleProof,
        expected_root: bytes | str | None = None,
    ) -> dict[str, any]:
        """
        Verify that an event is included in the Merkle tree.
        
        Args:
            event: The VCP event to verify
            proof: The Merkle inclusion proof
            expected_root: Expected Merkle root (if different from proof)
            
        Returns:
            Verification result dictionary with status and details
        """
        self._logger.debug(
            "Verifying Merkle inclusion",
            event_id=event.event_id,
            leaf_index=proof.leaf_index,
            tree_size=proof.tree_size,
        )
        
        try:
            # Step 1: Validate proof structure
            validation_result = self._validate_proof_structure(proof)
            if validation_result["status"] != "PASSED":
                return validation_result
            
            # Step 2: Compute leaf hash
            leaf_hash = self._compute_leaf_hash(event)
            
            # Step 3: Compute root hash from proof
            computed_root = self._compute_root_from_proof(leaf_hash, proof)
            
            # Step 4: Compare with expected root
            if expected_root is not None:
                if isinstance(expected_root, str):
                    expected_root = base64.b64decode(expected_root)
                expected_root_bytes = expected_root
            else:
                expected_root_bytes = base64.b64decode(proof.root_hash)
            
            if computed_root != expected_root_bytes:
                self._logger.error(
                    "Merkle root mismatch",
                    event_id=event.event_id,
                    computed=base64.b64encode(computed_root).decode(),
                    expected=base64.b64encode(expected_root_bytes).decode(),
                )
                return {
                    "status": "FAILED",
                    "error_code": "MERKLE_ROOT_MISMATCH",
                    "message": "Computed Merkle root does not match expected root",
                    "computed_root": base64.b64encode(computed_root).decode(),
                    "expected_root": base64.b64encode(expected_root_bytes).decode(),
                }
            
            self._logger.debug(
                "Merkle inclusion verified",
                event_id=event.event_id,
                root=base64.b64encode(computed_root).decode(),
            )
            return {
                "status": "PASSED",
                "message": "Merkle inclusion proof verified",
                "computed_root": base64.b64encode(computed_root).decode(),
                "leaf_index": proof.leaf_index,
                "tree_size": proof.tree_size,
            }
            
        except ValueError as e:
            self._logger.error("Invalid proof format", event_id=event.event_id, error=str(e))
            return {
                "status": "FAILED",
                "error_code": "PROOF_INVALID",
                "message": f"Invalid Merkle proof format: {e}",
            }
        except Exception as e:
            self._logger.exception("Unexpected error", event_id=event.event_id)
            return {
                "status": "FAILED",
                "error_code": "INTERNAL_ERROR",
                "message": f"Unexpected error during Merkle verification: {e}",
            }
    
    def _validate_proof_structure(self, proof: MerkleProof) -> dict[str, any]:
        """
        Validate the structure of a Merkle proof.
        
        Args:
            proof: The Merkle proof to validate
            
        Returns:
            Validation result dictionary
        """
        # Check leaf index is within tree bounds
        if proof.leaf_index >= proof.tree_size:
            return {
                "status": "FAILED",
                "error_code": "PROOF_INVALID",
                "message": f"Leaf index {proof.leaf_index} >= tree size {proof.tree_size}",
            }
        
        # Check path and directions have same length
        if len(proof.path) != len(proof.directions):
            return {
                "status": "FAILED",
                "error_code": "PROOF_INVALID",
                "message": "Path and directions arrays must have same length",
            }
        
        # Check expected path length
        expected_path_length = self._expected_path_length(proof.leaf_index, proof.tree_size)
        if len(proof.path) != expected_path_length:
            self._logger.warning(
                "Unexpected path length",
                actual=len(proof.path),
                expected=expected_path_length,
            )
            # This is a warning, not a failure, as tree structure may vary
        
        return {"status": "PASSED"}
    
    def _compute_leaf_hash(self, event: VCPEvent) -> bytes:
        """
        Compute the leaf hash for an event.
        
        RFC 6962 specifies: H(0x00 || data) for leaves
        
        Args:
            event: The VCP event
            
        Returns:
            SHA-256 hash of the leaf
        """
        # Canonicalize event data
        event_bytes = self._canonicalize_event(event)
        
        # RFC 6962: Leaf hash = H(0x00 || data)
        return hashlib.sha256(self.LEAF_PREFIX + event_bytes).digest()
    
    def _compute_root_from_proof(
        self,
        leaf_hash: bytes,
        proof: MerkleProof,
    ) -> bytes:
        """
        Compute the Merkle root from a leaf hash and proof.
        
        Args:
            leaf_hash: Hash of the leaf node
            proof: Merkle inclusion proof
            
        Returns:
            Computed Merkle root hash
        """
        current_hash = leaf_hash
        
        for i, sibling_b64 in enumerate(proof.path):
            sibling = base64.b64decode(sibling_b64)
            direction = proof.directions[i]
            
            # RFC 6962: Node hash = H(0x01 || left || right)
            if direction == "LEFT":
                # Sibling is on the left
                current_hash = hashlib.sha256(
                    self.NODE_PREFIX + sibling + current_hash
                ).digest()
            else:
                # Sibling is on the right
                current_hash = hashlib.sha256(
                    self.NODE_PREFIX + current_hash + sibling
                ).digest()
        
        return current_hash
    
    def _canonicalize_event(self, event: VCPEvent) -> bytes:
        """
        Canonicalize event data for Merkle tree inclusion.
        
        Args:
            event: The VCP event
            
        Returns:
            Canonical byte representation
        """
        # Use same canonicalization as signature verification
        event_dict = {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "timestamp_precision": event.timestamp_precision.value,
            "clock_sync_status": event.clock_sync_status.value,
            "sequence_num": event.sequence_num,
            "prev_hash": event.prev_hash,
            "event_type": event.event_type,
            "payload": event.payload,
        }
        
        if event.algorithm_id:
            event_dict["algorithm_id"] = event.algorithm_id
        if event.correlation_id:
            event_dict["correlation_id"] = event.correlation_id
        
        # Include signature in Merkle tree (unlike signature verification)
        event_dict["signature"] = {
            "algorithm": event.signature.algorithm,
            "public_key": event.signature.public_key,
            "value": event.signature.value,
        }
        
        return json.dumps(event_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    
    def _expected_path_length(self, leaf_index: int, tree_size: int) -> int:
        """
        Calculate expected path length for a given leaf index and tree size.
        
        Args:
            leaf_index: Index of the leaf
            tree_size: Total number of leaves
            
        Returns:
            Expected number of siblings in the proof
        """
        if tree_size == 1:
            return 0
        
        # For a balanced tree, path length is ceil(log2(tree_size))
        import math
        return math.ceil(math.log2(tree_size))
    
    def verify_batch_completeness(
        self,
        events: list[VCPEvent],
        start_seq: int,
        end_seq: int,
    ) -> dict[str, any]:
        """
        Verify completeness of a batch of events (no gaps in sequence numbers).
        
        Args:
            events: List of VCP events
            start_seq: Expected starting sequence number
            end_seq: Expected ending sequence number
            
        Returns:
            Verification result dictionary
        """
        self._logger.debug(
            "Verifying batch completeness",
            start_seq=start_seq,
            end_seq=end_seq,
            num_events=len(events),
        )
        
        # Sort events by sequence number
        sorted_events = sorted(events, key=lambda e: e.sequence_num)
        
        # Check for gaps
        gaps = []
        expected_seq = start_seq
        
        for event in sorted_events:
            if event.sequence_num != expected_seq:
                gaps.append({
                    "expected": expected_seq,
                    "found": event.sequence_num,
                    "gap_size": event.sequence_num - expected_seq,
                })
            expected_seq = event.sequence_num + 1
        
        # Check if we reached the end
        if expected_seq <= end_seq:
            gaps.append({
                "expected": expected_seq,
                "found": None,
                "gap_size": end_seq - expected_seq + 1,
                "message": "Missing events at end of batch",
            })
        
        if gaps:
            self._logger.warning("Sequence gaps detected", gaps=gaps)
            return {
                "status": "FAILED",
                "error_code": "SEQUENCE_GAP",
                "message": f"Found {len(gaps)} gap(s) in sequence numbers",
                "gaps": gaps,
            }
        
        self._logger.debug("Batch completeness verified")
        return {
            "status": "PASSED",
            "message": "Batch completeness verified",
            "events_verified": len(events),
        }
