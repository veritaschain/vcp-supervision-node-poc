# VCP Supervision Node API Reference

## Overview

The VCP Supervision Node provides both a Python API and a REST API (via the dashboard) for verification operations.

## Python API

### SupervisionNode

The main entry point for verification operations.

```python
from vcp_supervision import SupervisionNode

# Initialize with configuration file
node = SupervisionNode(config_path="config/default.yaml")

# Or with inline configuration
node = SupervisionNode(config={
    "verification": {
        "timing": {"default_jurisdiction": "EU"}
    }
})
```

#### Methods

##### `verify_event(event, proof, anchor, jurisdiction=None, entity_type="NON_HFT")`

Verify a single VCP event.

**Parameters:**
- `event` (VCPEvent): The VCP event to verify
- `proof` (MerkleProof): Merkle inclusion proof
- `anchor` (AnchorRecord): External anchor record
- `jurisdiction` (str, optional): Target jurisdiction (default: from config)
- `entity_type` (str): Entity type for timing requirements

**Returns:** `VerificationResult`

**Example:**
```python
result = node.verify_event(
    event=event,
    proof=proof,
    anchor=anchor,
    jurisdiction="EU",
    entity_type="HFT"
)

if result.is_compliant:
    print(f"Compliance score: {result.compliance_score}")
else:
    print(f"Failed: {result.error_code}")
```

##### `verify_batch(events, proofs, anchor, jurisdiction=None, entity_type="NON_HFT")`

Verify a batch of VCP events.

**Parameters:**
- `events` (list[VCPEvent]): List of events
- `proofs` (list[MerkleProof]): List of proofs (one per event)
- `anchor` (AnchorRecord): Shared anchor for the batch
- `jurisdiction` (str, optional): Target jurisdiction
- `entity_type` (str): Entity type

**Returns:** `list[VerificationResult]`

##### `generate_compliance_report(results, jurisdiction, report_id=None)`

Generate a compliance report from verification results.

**Parameters:**
- `results` (list[VerificationResult]): Verification results
- `jurisdiction` (str): Target jurisdiction
- `report_id` (str, optional): Report identifier

**Returns:** `ComplianceReport`

##### `get_stats()`

Get verification statistics.

**Returns:** `dict` with keys:
- `events_verified`: Total events verified
- `events_passed`: Events that passed
- `events_failed`: Events that failed
- `events_warning`: Events with warnings
- `started_at`: When the node started
- `uptime_seconds`: Uptime in seconds

---

### VerificationEngine

Lower-level verification engine with component access.

```python
from vcp_supervision.verification import VerificationEngine

engine = VerificationEngine(
    manifest=public_key_manifest,
    default_jurisdiction="UK",
    require_manifest=True
)
```

#### Component Verifiers

Access individual verification components:

```python
# Signature verification
sig_result = engine.signature_verifier.verify(event)

# Merkle proof verification
merkle_result = engine.merkle_verifier.verify(event, proof)

# Anchor verification
anchor_result = engine.anchor_verifier.verify(merkle_root, anchor)

# Timing verification
timing_result = engine.timing_verifier.verify(event, "EU", "HFT")
```

---

### Data Models

#### VCPEvent

```python
from vcp_supervision.models import VCPEvent, VCPSignature

event = VCPEvent(
    event_id="01234567-89ab-cdef-0123-456789abcdef",
    timestamp=datetime.now(timezone.utc),
    timestamp_precision=TimestampPrecision.MICROSECOND,
    clock_sync_status=ClockSyncStatus.PTP_LOCKED,
    sequence_num=1,
    prev_hash="0" * 64,
    event_type="ORDER_NEW",
    payload={"symbol": "EURUSD", "quantity": 1000},
    signature=VCPSignature(
        algorithm="Ed25519",
        public_key="base64_encoded_public_key",
        value="base64_encoded_signature"
    )
)
```

#### MerkleProof

```python
from vcp_supervision.models import MerkleProof

proof = MerkleProof(
    leaf_index=5,
    tree_size=100,
    root_hash="base64_encoded_root",
    path=["sibling1", "sibling2", "sibling3"],
    directions=["LEFT", "RIGHT", "LEFT"]
)
```

#### AnchorRecord

```python
from vcp_supervision.models import AnchorRecord, AnchorType, TSAAnchor

anchor = AnchorRecord(
    anchor_type=AnchorType.TSA,
    merkle_root="base64_encoded_root",
    anchor_timestamp=datetime.now(timezone.utc),
    batch_start_seq=0,
    batch_end_seq=99,
    tsa_anchor=TSAAnchor(
        tsa_url="https://timestamp.digicert.com",
        token="base64_encoded_tsp_response",
        timestamp=datetime.now(timezone.utc),
        is_eidas_qualified=True
    )
)
```

#### VerificationResult

```python
result = node.verify_event(event, proof, anchor)

# Access properties
result.status          # VerificationStatus (PASSED, FAILED, WARNING)
result.error_code      # Error code if failed
result.message         # Human-readable message
result.compliance_score  # 0.0 to 1.0
result.signature_valid # bool
result.merkle_valid    # bool
result.anchor_valid    # bool
result.timing_valid    # bool
result.is_compliant    # Property: True if status is PASSED or WARNING
result.details         # Full verification details
```

---

## REST API (Dashboard)

When the dashboard is running, the following endpoints are available:

### Health Check

```
GET /api/health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2026-01-26T12:00:00Z",
  "node_stats": {...}
}
```

### Statistics

```
GET /api/stats
```

**Response:**
```json
{
  "events_verified": 1000,
  "events_passed": 980,
  "events_failed": 10,
  "events_warning": 10,
  "pass_rate": 0.98,
  "active_alerts": 5
}
```

### Verification Results

```
GET /api/results?limit=100&status=FAILED
```

**Query Parameters:**
- `limit` (int): Maximum results to return (default: 100)
- `status` (str, optional): Filter by status (PASSED, FAILED, WARNING)

**Response:**
```json
[
  {
    "status": "FAILED",
    "error_code": "SIG_INVALID",
    "compliance_score": 0.0,
    "received_at": "2026-01-26T12:00:00Z"
  }
]
```

### Add Result

```
POST /api/results
Content-Type: application/json

{
  "status": "PASSED",
  "compliance_score": 0.95,
  ...
}
```

### Alerts

```
GET /api/alerts?limit=50&acknowledged=false
```

**Query Parameters:**
- `limit` (int): Maximum alerts to return (default: 50)
- `acknowledged` (bool, optional): Filter by acknowledgement status

### Acknowledge Alert

```
POST /api/alerts/{alert_id}/acknowledge
```

### Compliance Score

```
GET /api/compliance/score?jurisdiction=EU
```

**Query Parameters:**
- `jurisdiction` (str): Jurisdiction code (default: EU)

**Response:**
```json
{
  "jurisdiction": "EU",
  "score": 0.95,
  "total_events": 1000,
  "integrity_score": 0.98,
  "timing_score": 0.92
}
```

---

## CLI Reference

### Verify Events

```bash
vcp-supervision verify events.json \
  --jurisdiction EU \
  --entity-type HFT \
  --output results.json
```

### Generate Report

```bash
vcp-supervision report results.json \
  --jurisdiction EU \
  --output compliance_report.json
```

### Start Dashboard

```bash
vcp-supervision dashboard --host 0.0.0.0 --port 8080
```

### Display Timing Requirements

```bash
# All jurisdictions
vcp-supervision timing

# Specific jurisdiction
vcp-supervision timing --jurisdiction EU
```

---

## Error Codes

| Code | Description | Regulatory Impact |
|------|-------------|-------------------|
| `SIG_INVALID` | Ed25519 signature verification failed | SEC 17a-4, eIDAS |
| `KEY_NOT_AUTHORIZED` | Public key not in manifest | Entity authorization |
| `KEY_REVOKED` | Public key has been revoked | Key management |
| `MERKLE_ROOT_MISMATCH` | Computed root doesn't match expected | Integrity violation |
| `SEQUENCE_GAP` | Gap detected in sequence numbers | Completeness failure |
| `TSA_NOT_TRUSTED` | TSA URL not in trusted list | eIDAS compliance |
| `TSA_TOKEN_INVALID` | TSA token format invalid | RFC 3161 |
| `BC_ROOT_MISMATCH` | Blockchain anchor mismatch | Anchor integrity |
| `BC_LOW_CONFIRMATIONS` | Insufficient blockchain confirmations | Finality |
| `CLOCK_UNRELIABLE` | Clock sync status unreliable | RTS 25 |
| `PRECISION_INSUFFICIENT` | Timestamp precision too low | RTS 25 |
| `TIMESTAMP_REGRESSION` | Timestamp ordering violation | RTS 25 |

---

## Jurisdictions Supported

| Code | Jurisdiction | Primary Regulations |
|------|-------------|---------------------|
| `EU` | European Union | MiFID II, RTS 25, DORA |
| `UK` | United Kingdom | UK MiFID II, PS21/3 |
| `US` | United States | SEC 17a-4, CAT NMS |
| `JP` | Japan | FIEA |
| `SG` | Singapore | MAS TRM |
| `HK` | Hong Kong | SFC Guidelines |
| `AU` | Australia | ASIC MIR |
| `CA` | Canada | NI 23-103 |
| `CH` | Switzerland | FINMA |

---

*VeritasChain Standards Organization*  
*"Verify, Don't Trust"*
