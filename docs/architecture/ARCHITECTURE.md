# VCP Supervision Node Architecture

**Document ID:** VSO-ARCH-POC-001  
**Version:** 1.0  
**Last Updated:** January 2026

---

## 1. Overview

The VCP Supervision Node is a **Layer 2 Audit Overlay** that enables regulatory authorities to independently verify the integrity of algorithmic trading logs without requiring firms to change their existing trading infrastructure.

### Design Principles

| Principle | Description |
|-----------|-------------|
| **Non-invasive** | Works alongside existing MT4/MT5/cTrader/FIX systems |
| **Zero Trust** | Never trust submitted data; always verify cryptographic proofs |
| **Independence** | No dependency on firm's infrastructure for verification |
| **Regulatory Alignment** | Built to satisfy RTS 25, DORA, SEC 17a-4, CAT NMS |

---

## 2. System Context

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              EXTERNAL CONTEXT                                │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                     MARKET PARTICIPANTS                              │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │   │
│  │  │  Firm A     │  │  Firm B     │  │  Firm C     │                  │   │
│  │  │  MT4/MT5    │  │  cTrader    │  │  FIX Engine │                  │   │
│  │  │  + VCP      │  │  + VCP      │  │  + VCP      │                  │   │
│  │  │  Sidecar    │  │  Sidecar    │  │  Sidecar    │                  │   │
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                  │   │
│  └─────────┼────────────────┼────────────────┼─────────────────────────┘   │
│            │                │                │                              │
│            │                │                │                              │
│            ▼                ▼                ▼                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    EXTERNAL ANCHORING SERVICES                       │   │
│  │  ┌───────────────────────┐  ┌───────────────────────┐               │   │
│  │  │  Timestamp Authority  │  │  Public Blockchain    │               │   │
│  │  │  (RFC 3161)           │  │  (Ethereum, etc.)     │               │   │
│  │  │  - DigiCert           │  │                       │               │   │
│  │  │  - FreeTSA            │  │                       │               │   │
│  │  └───────────────────────┘  └───────────────────────┘               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│            │                                │                              │
│            │                                │                              │
│            ▼                                ▼                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                                                                      │   │
│  │                    VCP SUPERVISION NODE                              │   │
│  │                    (This System)                                     │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│            │                                                               │
│            ▼                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                     REGULATORY AUTHORITY                             │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │   │
│  │  │  Compliance │  │  Enforcement│  │  Policy     │                  │   │
│  │  │  Officers   │  │  Division   │  │  Makers     │                  │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘                  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        VCP SUPERVISION NODE                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         API LAYER                                    │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │   │
│  │  │ REST API    │  │ WebSocket   │  │ CLI         │                  │   │
│  │  │ (FastAPI)   │  │ (Real-time) │  │ Interface   │                  │   │
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                  │   │
│  └─────────┼────────────────┼────────────────┼─────────────────────────┘   │
│            │                │                │                              │
│            └────────────────┼────────────────┘                              │
│                             │                                               │
│                             ▼                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    SUPERVISION NODE CORE                             │   │
│  │  ┌─────────────────────────────────────────────────────────────┐    │   │
│  │  │                  SupervisionNode                             │    │   │
│  │  │  - verify_event()                                            │    │   │
│  │  │  - verify_batch()                                            │    │   │
│  │  │  - generate_compliance_report()                              │    │   │
│  │  │  - handle_challenge_request()                                │    │   │
│  │  └─────────────────────────────────────────────────────────────┘    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                             │                                               │
│                             ▼                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                   VERIFICATION ENGINE                                │   │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌─────────────┐ │   │
│  │  │  Signature   │ │  Merkle      │ │  Anchor      │ │  Timing     │ │   │
│  │  │  Verifier    │ │  Verifier    │ │  Verifier    │ │  Verifier   │ │   │
│  │  │              │ │              │ │              │ │             │ │   │
│  │  │  - Ed25519   │ │  - RFC 6962  │ │  - TSA       │ │  - RTS 25   │ │   │
│  │  │  - Manifest  │ │  - Inclusion │ │  - Blockchain│ │  - CAT NMS  │ │   │
│  │  │    lookup    │ │    proofs    │ │  - Dual      │ │  - 10 juris.│ │   │
│  │  └──────────────┘ └──────────────┘ └──────────────┘ └─────────────┘ │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                             │                                               │
│            ┌────────────────┼────────────────┐                              │
│            │                │                │                              │
│            ▼                ▼                ▼                              │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐               │
│  │   REPORTING     │ │   DASHBOARD     │ │   PERSISTENCE   │               │
│  │                 │ │                 │ │                 │               │
│  │  - DORA         │ │  - Real-time    │ │  - Results DB   │               │
│  │  - Compliance   │ │  - Alerts       │ │  - Alert Store  │               │
│  │  - FCA MAR 7A   │ │  - Scores       │ │  - Report Store │               │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Data Flow

### 4.1 Standard Verification Flow

```
┌─────────┐     ┌─────────────────┐     ┌─────────────────┐     ┌──────────┐
│  Firm   │────▶│  VCP Sidecar    │────▶│  External Anchor│────▶│ Regulator│
│(Trading)│     │  (Firm-side)    │     │  (TSA/BC)       │     │ (Node)   │
└─────────┘     └─────────────────┘     └─────────────────┘     └──────────┘
     │                  │                       │                     │
     │  1. Trading      │                       │                     │
     │     Events       │                       │                     │
     │─────────────────▶│                       │                     │
     │                  │                       │                     │
     │                  │  2. Hash Chain        │                     │
     │                  │     + Signature       │                     │
     │                  │                       │                     │
     │                  │  3. Batch to          │                     │
     │                  │     Merkle Tree       │                     │
     │                  │─────────────────────▶│                     │
     │                  │                       │                     │
     │                  │  4. Anchor Root       │                     │
     │                  │◀─────────────────────│                     │
     │                  │                       │                     │
     │                  │  5. Submit Batch      │                     │
     │                  │     + Proof + Anchor  │                     │
     │                  │──────────────────────────────────────────▶│
     │                  │                       │                     │
     │                  │                       │  6. Verify:         │
     │                  │                       │     - Signature     │
     │                  │                       │     - Merkle Proof  │
     │                  │                       │     - Anchor        │
     │                  │                       │     - Timing        │
     │                  │                       │                     │
     │                  │                       │  7. Score & Report  │
     │                  │                       │◀────────────────────│
```

### 4.2 On-Demand Challenge Flow (Assertion C)

```
┌──────────┐                              ┌──────────┐                ┌─────────┐
│ Regulator│                              │   Firm   │                │  TSA/BC │
│  (Node)  │                              │(Sidecar) │                │         │
└────┬─────┘                              └────┬─────┘                └────┬────┘
     │                                         │                           │
     │  1. Challenge Request                   │                           │
     │     (event_id, batch_id)                │                           │
     │────────────────────────────────────────▶│                           │
     │                                         │                           │
     │                                         │  2. Retrieve event        │
     │                                         │     from local store      │
     │                                         │                           │
     │                                         │  3. Generate Merkle path  │
     │                                         │                           │
     │  4. Challenge Response                  │                           │
     │     (event, proof, anchor)              │                           │
     │◀────────────────────────────────────────│                           │
     │                                         │                           │
     │  5. Verify anchor independently         │                           │
     │────────────────────────────────────────────────────────────────────▶│
     │                                         │                           │
     │  6. Anchor confirmation                 │                           │
     │◀────────────────────────────────────────────────────────────────────│
     │                                         │                           │
     │  7. Verify proof against                │                           │
     │     confirmed root                      │                           │
     │                                         │                           │
     │  8. Result (PASS/FAIL)                  │                           │
     │                                         │                           │
```

---

## 5. Verification Layers

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         VERIFICATION STACK                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  LAYER 4: REGULATORY COMPLIANCE                                      │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │   │
│  │  │  RTS 25     │  │  CAT NMS    │  │  DORA       │                  │   │
│  │  │  Timing     │  │  Timing     │  │  Reporting  │                  │   │
│  │  │  100µs/1ms  │  │  50ms/100µs │  │  4h/72h/30d │                  │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘                  │   │
│  │  Answers: "Does this meet regulatory timing/reporting requirements?" │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  LAYER 3: TEMPORAL INTEGRITY (External Verifiability)                │   │
│  │  ┌─────────────────────────────┐  ┌─────────────────────────────┐   │   │
│  │  │  TSA Anchor (RFC 3161)      │  │  Blockchain Anchor          │   │   │
│  │  │  - Token verification       │  │  - Transaction lookup       │   │   │
│  │  │  - Trusted TSA check        │  │  - Confirmation count       │   │   │
│  │  │  - eIDAS qualified?         │  │  - Root in TX data          │   │   │
│  │  └─────────────────────────────┘  └─────────────────────────────┘   │   │
│  │  Answers: "Can we prove this root existed at a specific time?"       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  LAYER 2: COLLECTION INTEGRITY (Merkle Tree)                         │   │
│  │  ┌─────────────────────────────────────────────────────────────┐    │   │
│  │  │  RFC 6962 Merkle Verification                                │    │   │
│  │  │  - Leaf hash: H(0x00 || event_bytes)                         │    │   │
│  │  │  - Node hash: H(0x01 || left || right)                       │    │   │
│  │  │  - Inclusion proof verification                              │    │   │
│  │  │  - Root reconstruction                                       │    │   │
│  │  └─────────────────────────────────────────────────────────────┘    │   │
│  │  Answers: "Is this event included in the batch without tampering?"   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  LAYER 1: EVENT INTEGRITY (Hash Chain + Signature)                   │   │
│  │  ┌─────────────────────────────┐  ┌─────────────────────────────┐   │   │
│  │  │  Ed25519 Signature          │  │  Hash Chain (prev_hash)     │   │   │
│  │  │  - RFC 8032 compliance      │  │  - Sequence number check    │   │   │
│  │  │  - Manifest key lookup      │  │  - Gap detection            │   │   │
│  │  │  - Revocation check         │  │  - Ordering verification    │   │   │
│  │  └─────────────────────────────┘  └─────────────────────────────┘   │   │
│  │  Answers: "Is this event authentic and in correct sequence?"         │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Trust Boundaries

### 6.1 Trust Zones

| Zone | Components | Trust Level | Data Sensitivity |
|------|------------|-------------|------------------|
| **Zone 0: Untrusted** | Firm submissions | None | Raw events |
| **Zone 1: Semi-trusted** | TSA/Blockchain | Conditional | Anchor tokens |
| **Zone 2: Trusted** | Verification Engine | High | Cryptographic operations |
| **Zone 3: Protected** | Results storage | High | Compliance data |

### 6.2 Trust Boundary Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   ZONE 0: UNTRUSTED                                                         │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │  Firm Submissions (Events, Proofs, Anchor References)               │  │
│   │  - May be malformed                                                 │  │
│   │  - May be tampered                                                  │  │
│   │  - May contain forged signatures                                    │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
│                                    │                                        │
│                                    ▼                                        │
│   ════════════════════════════════════════════════════════════════════════ │
│   │ VALIDATION BOUNDARY: Input validation, schema check, size limits    │  │
│   ════════════════════════════════════════════════════════════════════════ │
│                                    │                                        │
│                                    ▼                                        │
│   ZONE 1: SEMI-TRUSTED                                                      │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │  External Anchors                                                   │  │
│   │  - TSA: Trusted if in allowlist and token valid                     │  │
│   │  - Blockchain: Trusted if sufficient confirmations                  │  │
│   │  - May be unavailable (network issues)                              │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
│                                    │                                        │
│                                    ▼                                        │
│   ════════════════════════════════════════════════════════════════════════ │
│   │ CRYPTOGRAPHIC BOUNDARY: All verification happens here               │  │
│   ════════════════════════════════════════════════════════════════════════ │
│                                    │                                        │
│                                    ▼                                        │
│   ZONE 2: TRUSTED                                                           │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │  Verification Engine                                                │  │
│   │  - Ed25519 verification (cryptography library)                      │  │
│   │  - SHA-256 computation (hashlib)                                    │  │
│   │  - Merkle proof reconstruction                                      │  │
│   │  - No external network calls                                        │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
│                                    │                                        │
│                                    ▼                                        │
│   ════════════════════════════════════════════════════════════════════════ │
│   │ STORAGE BOUNDARY: Only verified data crosses this                   │  │
│   ════════════════════════════════════════════════════════════════════════ │
│                                    │                                        │
│                                    ▼                                        │
│   ZONE 3: PROTECTED                                                         │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │  Results & Reports                                                  │  │
│   │  - Verification results (pass/fail/score)                           │  │
│   │  - Compliance reports                                               │  │
│   │  - Alert history                                                    │  │
│   │  - No raw payloads stored                                           │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 7. Scoring Model

### 7.1 Compliance Score Calculation

```
Total Score = (Signature × 0.30) + (Merkle × 0.25) + (Anchor × 0.25) + (Timing × 0.20)

Where each component is 0.0 (failed) or 1.0 (passed)
```

### 7.2 Score Breakdown

| Component | Weight | Pass Criteria |
|-----------|--------|---------------|
| **Signature** | 30% | Ed25519 valid, key authorized, not revoked |
| **Merkle** | 25% | Proof verifies, root matches anchor |
| **Anchor** | 25% | TSA in allowlist OR blockchain confirmed |
| **Timing** | 20% | Precision sufficient, clock sync acceptable |

### 7.3 Status Determination

| Score Range | Status | Interpretation |
|-------------|--------|----------------|
| 1.00 | PASSED | Fully compliant |
| 0.80 - 0.99 | WARNING | Minor issues (e.g., timing borderline) |
| < 0.80 | FAILED | Significant compliance failure |

---

## 8. Module Dependencies

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        MODULE DEPENDENCY GRAPH                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐                                                            │
│  │   models    │◀────────────────────────────────────────────────────┐     │
│  │             │                                                      │     │
│  │  VCPEvent   │                                                      │     │
│  │  MerkleProof│                                                      │     │
│  │  AnchorRec. │                                                      │     │
│  └──────┬──────┘                                                      │     │
│         │                                                             │     │
│         ▼                                                             │     │
│  ┌─────────────────────────────────────────────────────────────┐     │     │
│  │                    verification/                             │     │     │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐ │     │     │
│  │  │ signature │  │  merkle   │  │  anchor   │  │  timing   │ │     │     │
│  │  │   .py     │  │   .py     │  │   .py     │  │   .py     │ │     │     │
│  │  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘ │     │     │
│  │        │              │              │              │        │     │     │
│  │        └──────────────┼──────────────┼──────────────┘        │     │     │
│  │                       │              │                       │     │     │
│  │                       ▼              │                       │     │     │
│  │                 ┌───────────┐        │                       │     │     │
│  │                 │  engine   │◀───────┘                       │     │     │
│  │                 │   .py     │                                │     │     │
│  │                 └─────┬─────┘                                │     │     │
│  └───────────────────────┼──────────────────────────────────────┘     │     │
│                          │                                            │     │
│                          ▼                                            │     │
│                    ┌───────────┐                                      │     │
│                    │   node    │──────────────────────────────────────┘     │
│                    │   .py     │                                            │
│                    └─────┬─────┘                                            │
│                          │                                                  │
│          ┌───────────────┼───────────────┐                                  │
│          │               │               │                                  │
│          ▼               ▼               ▼                                  │
│    ┌───────────┐  ┌───────────┐  ┌───────────┐                             │
│    │ reporting │  │ dashboard │  │    cli    │                             │
│    │           │  │           │  │           │                             │
│    └───────────┘  └───────────┘  └───────────┘                             │
│                                                                             │
│  External Dependencies:                                                     │
│  ├── cryptography (Ed25519)                                                 │
│  ├── pydantic (data models)                                                 │
│  ├── httpx (async HTTP for TSA/BC)                                          │
│  ├── structlog (logging)                                                    │
│  └── fastapi (optional: dashboard/API)                                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 9. Deployment Topologies

### 9.1 Standalone (PoC/Development)

```
┌─────────────────────────────────────┐
│  Single Server                       │
│  ┌─────────────────────────────────┐│
│  │  VCP Supervision Node           ││
│  │  + SQLite                       ││
│  │  + Embedded Dashboard           ││
│  └─────────────────────────────────┘│
└─────────────────────────────────────┘
```

### 9.2 Production (Single Region)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Production Deployment                                                       │
│                                                                             │
│  ┌─────────────┐     ┌─────────────────────────────────────┐               │
│  │ Load        │────▶│  VCP Supervision Nodes (HA)         │               │
│  │ Balancer    │     │  ┌─────────┐  ┌─────────┐           │               │
│  └─────────────┘     │  │ Node 1  │  │ Node 2  │           │               │
│                      │  └─────────┘  └─────────┘           │               │
│                      └─────────────────┬───────────────────┘               │
│                                        │                                    │
│                      ┌─────────────────┼───────────────────┐               │
│                      │                 │                   │               │
│                      ▼                 ▼                   ▼               │
│               ┌───────────┐     ┌───────────┐       ┌───────────┐         │
│               │ PostgreSQL│     │ Redis     │       │ Prometheus│         │
│               │ (Primary) │     │ (Cache)   │       │ (Metrics) │         │
│               └───────────┘     └───────────┘       └───────────┘         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 10. Performance Targets

| Metric | Target | Rationale |
|--------|--------|-----------|
| Verification latency (p95) | < 100ms | Interactive dashboard use |
| Verification latency (p99) | < 500ms | Batch processing acceptable |
| Throughput | 10,000 events/sec | Support multiple firms |
| Batch verification | 100 events/sec | Merkle completeness checks |
| Dashboard refresh | 5 seconds | Real-time feel |
| Alert generation | < 1 second | Immediate notification |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | January 2026 | Initial release |

---

**VeritasChain Standards Organization (VSO)**  
technical@veritaschain.org

*"Verify, Don't Trust"*
