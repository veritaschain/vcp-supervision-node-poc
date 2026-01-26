"""
Signature verification module.

Implements Ed25519 digital signature verification as per RFC 8032.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import TYPE_CHECKING

import structlog
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

if TYPE_CHECKING:
    from vcp_supervision.models import PublicKeyManifest, VCPEvent

logger = structlog.get_logger(__name__)


class SignatureVerificationError(Exception):
    """Raised when signature verification fails."""
    
    def __init__(self, error_code: str, message: str) -> None:
        self.error_code = error_code
        self.message = message
        super().__init__(message)


class SignatureVerifier:
    """
    Ed25519 signature verifier.
    
    Verifies that VCP events are properly signed by authorized entities
    using the Ed25519 digital signature algorithm.
    
    Regulatory Alignment:
    - SEC Rule 17a-4: Requires records to be unalterable
    - eIDAS Article 26: Advanced electronic signatures
    """
    
    def __init__(
        self,
        manifest: PublicKeyManifest | None = None,
        require_manifest: bool = True,
    ) -> None:
        """
        Initialize the signature verifier.
        
        Args:
            manifest: Public key manifest for authorized keys
            require_manifest: Whether to require key to be in manifest
        """
        self.manifest = manifest
        self.require_manifest = require_manifest
        self._logger = logger.bind(component="SignatureVerifier")
    
    def verify(self, event: VCPEvent) -> dict[str, any]:
        """
        Verify the digital signature of a VCP event.
        
        Args:
            event: The VCP event to verify
            
        Returns:
            Verification result dictionary with status and details
        """
        self._logger.debug("Verifying signature", event_id=event.event_id)
        
        try:
            # Step 1: Canonicalize the event for signature verification
            signed_data = self._canonicalize_event(event)
            
            # Step 2: Decode the public key and signature
            public_key_bytes = base64.b64decode(event.signature.public_key)
            signature_bytes = base64.b64decode(event.signature.value)
            
            # Step 3: Verify the Ed25519 signature
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            public_key.verify(signature_bytes, signed_data)
            
            # Step 4: Check if key is in manifest (if required)
            if self.require_manifest and self.manifest:
                key_fingerprint = self._compute_fingerprint(event.signature.public_key)
                
                if key_fingerprint not in self.manifest.authorized_keys:
                    self._logger.warning(
                        "Key not in manifest",
                        event_id=event.event_id,
                        fingerprint=key_fingerprint,
                    )
                    return {
                        "status": "FAILED",
                        "error_code": "KEY_NOT_AUTHORIZED",
                        "message": "Public key is not in authorized manifest",
                        "fingerprint": key_fingerprint,
                    }
                
                # Check if key is revoked
                auth_key = self.manifest.authorized_keys[key_fingerprint]
                if auth_key.revoked:
                    self._logger.warning(
                        "Key is revoked",
                        event_id=event.event_id,
                        fingerprint=key_fingerprint,
                        revoked_at=str(auth_key.revoked_at),
                    )
                    return {
                        "status": "FAILED",
                        "error_code": "KEY_REVOKED",
                        "message": "Public key has been revoked",
                        "fingerprint": key_fingerprint,
                        "revoked_at": str(auth_key.revoked_at),
                    }
            
            self._logger.debug("Signature valid", event_id=event.event_id)
            return {
                "status": "PASSED",
                "message": "Signature verification successful",
            }
            
        except InvalidSignature:
            self._logger.error("Invalid signature", event_id=event.event_id)
            return {
                "status": "FAILED",
                "error_code": "SIG_INVALID",
                "message": "Ed25519 signature verification failed",
            }
        except ValueError as e:
            self._logger.error("Invalid key format", event_id=event.event_id, error=str(e))
            return {
                "status": "FAILED",
                "error_code": "KEY_INVALID",
                "message": f"Invalid public key format: {e}",
            }
        except Exception as e:
            self._logger.exception("Unexpected error", event_id=event.event_id)
            return {
                "status": "FAILED",
                "error_code": "INTERNAL_ERROR",
                "message": f"Unexpected error during signature verification: {e}",
            }
    
    def _canonicalize_event(self, event: VCPEvent) -> bytes:
        """
        Canonicalize event data for signature verification.
        
        Uses deterministic JSON serialization to ensure consistent
        byte representation across implementations.
        
        Args:
            event: The VCP event to canonicalize
            
        Returns:
            Canonical byte representation of the event
        """
        # Create a dictionary with fields that are signed (excluding signature itself)
        signed_fields = {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "timestamp_precision": event.timestamp_precision.value,
            "clock_sync_status": event.clock_sync_status.value,
            "sequence_num": event.sequence_num,
            "prev_hash": event.prev_hash,
            "event_type": event.event_type,
            "payload": event.payload,
        }
        
        # Add optional fields if present
        if event.algorithm_id:
            signed_fields["algorithm_id"] = event.algorithm_id
        if event.correlation_id:
            signed_fields["correlation_id"] = event.correlation_id
        
        # Serialize with sorted keys for deterministic output
        canonical_json = json.dumps(signed_fields, sort_keys=True, separators=(",", ":"))
        return canonical_json.encode("utf-8")
    
    def _compute_fingerprint(self, public_key_b64: str) -> str:
        """
        Compute SHA-256 fingerprint of a public key.
        
        Args:
            public_key_b64: Base64-encoded public key
            
        Returns:
            Hex-encoded SHA-256 fingerprint
        """
        key_bytes = base64.b64decode(public_key_b64)
        return hashlib.sha256(key_bytes).hexdigest()
    
    def update_manifest(self, manifest: PublicKeyManifest) -> None:
        """
        Update the public key manifest.
        
        Args:
            manifest: New public key manifest
        """
        self._logger.info(
            "Updating manifest",
            manifest_id=manifest.manifest_id,
            version=manifest.version,
            num_keys=len(manifest.authorized_keys),
        )
        self.manifest = manifest
