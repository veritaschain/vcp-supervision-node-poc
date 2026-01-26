#!/usr/bin/env python3
"""
Example: Basic VCP Event Verification

This example demonstrates how to use the VCP Supervision Node
to verify a single VCP event with its Merkle proof and anchor.

Requirements:
    pip install vcp-supervision

Usage:
    python basic_verification.py
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vcp_supervision import SupervisionNode, VCPEvent, MerkleProof, AnchorRecord
from vcp_supervision.models import (
    AnchorType,
    AuthorizedKey,
    ClockSyncStatus,
    PublicKeyManifest,
    TimestampPrecision,
    TSAAnchor,
    VCPSignature,
)


def create_sample_event() -> tuple[VCPEvent, str]:
    """
    Create a sample VCP event with a valid Ed25519 signature.
    
    Returns:
        Tuple of (VCPEvent, public_key_b64)
    """
    # Generate a key pair
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes_raw()
    public_key_b64 = base64.b64encode(public_key_bytes).decode()
    
    # Create event data
    event_data = {
        "event_id": "01923456-789a-7def-8123-456789abcdef",
        "timestamp": datetime.now(timezone.utc),
        "timestamp_precision": TimestampPrecision.MILLISECOND,
        "clock_sync_status": ClockSyncStatus.NTP_SYNCED,
        "sequence_num": 1,
        "prev_hash": "0" * 64,
        "event_type": "ORDER_NEW",
        "payload": {
            "symbol": "EURUSD",
            "side": "BUY",
            "quantity": 100000,
            "price": 1.0850,
            "order_type": "LIMIT",
        },
    }
    
    # Canonicalize for signing (must match verifier's canonicalization)
    signed_fields = {
        "event_id": event_data["event_id"],
        "timestamp": event_data["timestamp"].isoformat(),
        "timestamp_precision": event_data["timestamp_precision"].value,
        "clock_sync_status": event_data["clock_sync_status"].value,
        "sequence_num": event_data["sequence_num"],
        "prev_hash": event_data["prev_hash"],
        "event_type": event_data["event_type"],
        "payload": event_data["payload"],
    }
    canonical = json.dumps(signed_fields, sort_keys=True, separators=(",", ":"))
    
    # Sign the event
    signature = private_key.sign(canonical.encode())
    signature_b64 = base64.b64encode(signature).decode()
    
    event = VCPEvent(
        **event_data,
        signature=VCPSignature(
            algorithm="Ed25519",
            public_key=public_key_b64,
            value=signature_b64,
        ),
    )
    
    return event, public_key_b64


def create_merkle_proof(event: VCPEvent) -> tuple[MerkleProof, bytes]:
    """
    Create a Merkle proof for a single-leaf tree.
    
    Args:
        event: The VCP event
        
    Returns:
        Tuple of (MerkleProof, root_hash_bytes)
    """
    # Canonicalize event for Merkle tree (includes signature)
    event_dict = {
        "event_id": event.event_id,
        "timestamp": event.timestamp.isoformat(),
        "timestamp_precision": event.timestamp_precision.value,
        "clock_sync_status": event.clock_sync_status.value,
        "sequence_num": event.sequence_num,
        "prev_hash": event.prev_hash,
        "event_type": event.event_type,
        "payload": event.payload,
        "signature": {
            "algorithm": event.signature.algorithm,
            "public_key": event.signature.public_key,
            "value": event.signature.value,
        },
    }
    event_bytes = json.dumps(event_dict, sort_keys=True, separators=(",", ":")).encode()
    
    # RFC 6962: Leaf hash = H(0x00 || data)
    leaf_hash = hashlib.sha256(b"\x00" + event_bytes).digest()
    
    # For a single-leaf tree, root = leaf hash
    root_hash = leaf_hash
    
    proof = MerkleProof(
        leaf_index=0,
        tree_size=1,
        root_hash=base64.b64encode(root_hash).decode(),
        path=[],
        directions=[],
    )
    
    return proof, root_hash


def create_anchor(merkle_root: bytes) -> AnchorRecord:
    """
    Create a sample anchor record.
    
    Args:
        merkle_root: The Merkle root to anchor
        
    Returns:
        AnchorRecord
    """
    return AnchorRecord(
        anchor_type=AnchorType.TSA,
        merkle_root=base64.b64encode(merkle_root).decode(),
        anchor_timestamp=datetime.now(timezone.utc),
        batch_start_seq=1,
        batch_end_seq=1,
        tsa_anchor=TSAAnchor(
            tsa_url="https://freetsa.org/tsr",
            token=base64.b64encode(b"mock-tsp-token-for-demo").decode(),
            timestamp=datetime.now(timezone.utc),
            is_eidas_qualified=False,
        ),
    )


def create_manifest(public_key_b64: str) -> PublicKeyManifest:
    """
    Create a public key manifest with the authorized key.
    
    Args:
        public_key_b64: Base64-encoded public key
        
    Returns:
        PublicKeyManifest
    """
    key_bytes = base64.b64decode(public_key_b64)
    fingerprint = hashlib.sha256(key_bytes).hexdigest()
    
    return PublicKeyManifest(
        manifest_id="demo-manifest-001",
        version=1,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        authorized_keys={
            fingerprint: AuthorizedKey(
                fingerprint=fingerprint,
                public_key=public_key_b64,
                algorithm="Ed25519",
                entity_name="Demo Trading Firm",
                entity_id="DEMO-001",
                valid_from=datetime(2024, 1, 1, tzinfo=timezone.utc),
            )
        },
    )


def main() -> None:
    """Run the verification example."""
    print("=" * 60)
    print("VCP Supervision Node - Basic Verification Example")
    print("=" * 60)
    print()
    
    # Step 1: Create sample data
    print("1. Creating sample VCP event with Ed25519 signature...")
    event, public_key_b64 = create_sample_event()
    print(f"   Event ID: {event.event_id}")
    print(f"   Event Type: {event.event_type}")
    print(f"   Clock Sync: {event.clock_sync_status.value}")
    print()
    
    # Step 2: Create Merkle proof
    print("2. Creating Merkle proof (single-leaf tree)...")
    proof, merkle_root = create_merkle_proof(event)
    print(f"   Root Hash: {base64.b64encode(merkle_root).decode()[:32]}...")
    print()
    
    # Step 3: Create anchor
    print("3. Creating TSA anchor record...")
    anchor = create_anchor(merkle_root)
    print(f"   Anchor Type: {anchor.anchor_type.value}")
    print(f"   TSA URL: {anchor.tsa_anchor.tsa_url}")
    print()
    
    # Step 4: Create manifest
    print("4. Creating public key manifest...")
    manifest = create_manifest(public_key_b64)
    print(f"   Manifest ID: {manifest.manifest_id}")
    print(f"   Authorized Keys: {len(manifest.authorized_keys)}")
    print()
    
    # Step 5: Initialize supervision node
    print("5. Initializing VCP Supervision Node...")
    node = SupervisionNode(
        manifest=manifest,
        config={
            "verification": {
                "signature": {"require_manifest": True},
                "timing": {"default_jurisdiction": "EU"},
            }
        },
    )
    print("   Node initialized successfully")
    print()
    
    # Step 6: Verify the event
    print("6. Verifying VCP event...")
    print("-" * 40)
    
    result = node.verify_event(
        event=event,
        proof=proof,
        anchor=anchor,
        jurisdiction="EU",
        entity_type="NON_HFT",
    )
    
    # Step 7: Display results
    print()
    print("VERIFICATION RESULTS")
    print("-" * 40)
    print(f"Overall Status:    {result.status.value}")
    print(f"Compliance Score:  {result.compliance_score:.1%}")
    print()
    print("Component Results:")
    print(f"  ✓ Signature:     {'PASSED' if result.signature_valid else 'FAILED'}")
    print(f"  ✓ Merkle Proof:  {'PASSED' if result.merkle_valid else 'FAILED'}")
    print(f"  ✓ Anchor:        {'PASSED' if result.anchor_valid else 'FAILED'}")
    print(f"  ✓ Timing:        {'PASSED' if result.timing_valid else 'FAILED'}")
    print()
    print(f"Jurisdiction:      {result.jurisdiction}")
    print(f"Elapsed Time:      {result.elapsed_seconds:.4f}s")
    
    if result.warnings:
        print()
        print("Warnings:")
        for warning in result.warnings:
            print(f"  ⚠ {warning}")
    
    print()
    print("=" * 60)
    print("Verification complete!")
    print("=" * 60)
    
    # Cleanup
    node.close()


if __name__ == "__main__":
    main()
