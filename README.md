> **Status correction — 25 October 2026; scope clarified 30 October 2026**
>
> - This is first-party proof-of-concept code by VeritasChain Co., Ltd., which operates the VeritasChain Standards Organization (VSO). It targets VCP v1.1. VCP v1.1 has no tagged release and is superseded by VCP v1.2 (Released, tag `v1.2.0`).
> - Conformance to any VCP tier, or to VAP, has not been independently established. There are zero external implementations of VAP or any of its profiles, including VCP.
> - Not certified. VSO does not issue certifications itself. The certification scheme requires a Conformity Assessment Body (CAB) independent of the scheme owner; the only registered CAB, VeritasChain Co., Ltd., is not independent (VAP v1.2 ERRATA E-2026-10-21).
> - **Anchor verification is incomplete.** The TSA path in `src/vcp_supervision/verification/anchor.py` decodes base64 and checks a URL allowlist; it does not parse or authenticate the timestamp token or bind its message imprint to the Merkle root. The blockchain path compares caller-supplied root and confirmation fields; without a configured RPC it can pass without an online check, and the optional RPC check only tests transaction existence, not whether transaction data commits to the root.
> - **Authentication placeholders.** In `src/vcp_supervision/api/auth.py`, `JWTAuth` accepts bearer strings without validating signatures or claims. `MTLSAuth` reads a certificate-identity header without validating a certificate itself. `APIKeyAuth` separately checks a configured key map.
> - **Result scope.** `PASSED`, `is_compliant`, "compliance scores", and regulatory-alignment tables are local indicators or design intent, not regulatory compliance findings. `is_compliant` is also true for `WARNING`. The `is_eidas_qualified`, `legal_presumption`, and `has_legal_presumption` flags do not establish qualified trust-service status or a legal conclusion.
> - **Batch checks.** `VerificationEngine.verify_batch()` logs sequence-range completeness and timestamp-ordering failures without changing the returned per-event results. Per-event success therefore does not establish batch completeness or ordering.

# VCP Supervision Node - Proof of Concept

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![VCP Version](https://img.shields.io/badge/VCP-v1.1-green.svg)](https://github.com/veritaschain/vcp-spec)

> **What it is:** A regulator-side verification node for VCP trading audit trails  
> **What it checks:** Selected signature, Merkle inclusion, and timing-metadata checks; external-anchor verification is incomplete  
> **What it outputs:** PoC status indicators and evidence bundles within the limitations above

---

**"Verify, Don't Trust"**

## Overview

The VCP Supervision Node is a first-party Proof of Concept (PoC) exploring regulator-side review of submitted trading logs. It implements selected local checks and reporting structures, with incomplete external-anchor verification and authentication placeholders. It does not establish independent deployment, complete capture of trading activity, or regulatory compliance.

### Current Checks and Design Targets

| Component | Current scope | Intended regulatory relevance (not compliance) |
|-----------|-------------|---------------------|
| **Signature Verification** | Ed25519 digital signature validation | SEC Rule 17a-4, eIDAS |
| **Merkle Proof Verification** | Merkle inclusion-proof checks | MiFID II Article 17 |
| **External Anchor Checks** | Incomplete TSA and blockchain checks; see limitations above | eIDAS Article 42 |
| **Timing Requirements Check** | Submitted clock-sync and precision metadata checks | EU RTS 25, CAT NMS |
| **Batch Sequence Checks** | Sequence-range checks; failures are logged without updating per-event status | DORA, MiFID II |
| **Incident Reporting Support** | DORA-aligned data preparation | DORA Article 19-23 |

### Core Principle: Verify, Don't Trust

```
Traditional Model:
  Firm ──[Self-reported logs]──> Regulator ──[Trust]──> Accept

VCP Model:
  Firm ──[Merkle Proof + Anchor]──> Regulator ──[Verify]──> Accept/Reject
          ↑                              ↓
     Third-party Anchor ←────[Independent Check]
     (TSA/Blockchain)
```

## Quick Start

### Prerequisites

- Python 3.10+
- pip or poetry

### Installation

```bash
# Clone the repository
git clone https://github.com/veritaschain/vcp-supervision-node-poc.git
cd vcp-supervision-node-poc

# Install dependencies
pip install -e .

# Or using poetry
poetry install
```

### Basic Usage

```python
from vcp_supervision import SupervisionNode
from vcp_supervision.verification import VerificationEngine

# Initialize the supervision node
node = SupervisionNode(config_path="config/default.yaml")

# Verify a single VCP event with its proof
result = node.verify_event(
    event=event_data,
    merkle_proof=proof_data,
    anchor_record=anchor_data
)

print(f"Verification Status: {result.status}")  # PASSED, FAILED, WARNING
print(f"Compliance Score: {result.score}")
```

### Running the Dashboard

```bash
# Start the compliance dashboard
python -m vcp_supervision.dashboard --port 8080

# Access at http://localhost:8080
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    VCP Supervision Node                              │
├─────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                  Verification Engine                         │    │
│  ├──────────────┬──────────────┬──────────────┬─────────────────┤    │
│  │ Signature    │ Merkle       │ Anchor       │ Timing          │    │
│  │ Verifier     │ Verifier     │ Verifier     │ Verifier        │    │
│  │ (Ed25519)    │ (RFC 6962)   │ (TSA/BC)     │ (RTS 25/CAT)    │    │
│  └──────────────┴──────────────┴──────────────┴─────────────────┘    │
│                              │                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                  Compliance Dashboard                        │    │
│  ├──────────────┬──────────────┬──────────────┬─────────────────┤    │
│  │ Score        │ Alert        │ Report       │ DORA            │    │
│  │ Display      │ Manager      │ Generator    │ Support         │    │
│  └──────────────┴──────────────┴──────────────┴─────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

## Innovation & Prior Art Analysis

The linked prior-art report is repository-authored design research. It does not establish independent deployment, complete external-anchor verification, or a world-first result. The comparisons below describe the proposed design and must be read with the implementation limitations above.

> **Design goal:** Explore regulator-side review of Merkle proof-based financial trading logs with external anchoring.

### Key Architectural Distinction

Prior "Supervisory Node" concepts and VCP Supervision Node differ fundamentally in architecture:

| Approach | Examples | Architecture | Limitation |
|----------|----------|--------------|------------|
| **Layer 1 (Prior Art)** | Boston Fed, MAS Project Ubin | Blockchain consensus participant | Requires firms to migrate to DLT |
| **Layer 2 (VCP)** | This PoC | Audit Overlay on existing systems | Works with MT4/cTrader/FIX as-is |

### Evaluated Counterexamples

This PoC was evaluated against 15+ potential counterexamples:

| Prior Art | Similarity | Critical Difference |
|-----------|------------|---------------------|
| Certificate Transparency (RFC 9162) | Merkle proofs, third-party monitors | TLS certificates, not trading logs |
| IETF SCITT Architecture | Transparency logs, Verifier role | Software supply chain, not financial |
| Boston Fed Supervisory Node | "Supervisory" name | Layer 1 consensus, not Layer 2 overlay |
| BIS Embedded Supervision | Regulatory technology concept | Blockchain-native, not hybrid audit |
| SEC CAT | Trading audit trail | Centralized database, no crypto proofs |
| Guardtime KSI | Merkle trees, timestamps | Enterprise data, not trading-specific |

### Comparative Analysis

| Feature | VCP Supervision Node | SEC CAT | Eventus Validus | Boston Fed Node |
|---------|---------------------|---------|-----------------|-----------------|
| Primary Purpose | Forensic Integrity | Reporting | Surveillance | DLT Participation |
| Trust Basis | Mathematics (Merkle) | Authority | Database | Consensus |
| External Anchor | Incomplete verification paths | No | No | Blockchain-native |
| Works with Existing Infrastructure | Yes | N/A | Yes | No (requires DLT) |
| Cryptographic Verification | Yes | No | No | Yes (L1) |

See [docs/world-first/WORLD_FIRST.md](docs/world-first/WORLD_FIRST.md) for complete analysis including methodology, confidence levels, and all 15+ counterexamples.

*Note: This determination is based on publicly accessible information. VSO welcomes information about any prior art that may have been missed.*

---

## Regulatory Alignment

This PoC is designed to align with requirements from 9 jurisdictions (design intent; compliance is not determined):

| Jurisdiction | Key Regulations | Timestamp Precision | Retention |
|-------------|-----------------|---------------------|-----------|
| **EU** | MiFID II, RTS 25, DORA, AI Act | 100µs (HFT) | 5-10 years |
| **UK** | UK MiFID II, PS21/3, FCA MAR 7A | 100µs (HFT) | 5-7 years |
| **US** | SEC 17a-4, CAT NMS, Reg SCI | 50ms-100µs | 3-6 years |
| **Japan** | FIEA, Cabinet Office Ordinance 338 | ms recommended | 7-10 years |
| **Singapore** | MAS TRM Guidelines | 1 second | 5 years |
| **Hong Kong** | SFC Electronic Trading Guidelines | µs (HFT) | 7 years |
| **Australia** | ASIC Market Integrity Rules | ms | 7 years |
| **Canada** | NI 23-103, UMIR | 50ms | 7 years |
| **Switzerland** | FINMA Circular 2013/8 | MiFID-like | 5-10 years |

### Evidence Grade Classification

All regulatory references are classified by evidence strength:

- **Primary Law**: EU Regulations, national laws (highest authority)
- **RTS/ITS**: Delegated/implementing regulations
- **Regulator Rule**: FCA Handbook, SEC Rules
- **Regulator Guidance**: Supervisory guidance (soft law)
- **SRO Rule**: FINRA rules, exchange rules

## Project Structure

```
vcp-supervision-node-poc/
├── src/
│   └── vcp_supervision/
│       ├── __init__.py
│       ├── node.py              # Main SupervisionNode class
│       ├── models.py            # Data models
│       ├── cli.py               # Command-line interface
│       ├── api/                 # REST API (FastAPI)
│       │   ├── server.py
│       │   ├── routes.py
│       │   └── auth.py          # Authentication (placeholder)
│       ├── verification/
│       │   ├── engine.py        # VerificationEngine
│       │   ├── signature.py     # Ed25519 verification
│       │   ├── merkle.py        # RFC 6962 Merkle verification
│       │   ├── anchor.py        # TSA/Blockchain anchor verification
│       │   └── timing.py        # RTS 25/CAT timing verification
│       ├── reporting/
│       │   └── incident/        # Incident reporting support
│       │       └── dora.py      # DORA support tools
│       └── dashboard/
│           └── app.py           # Web dashboard
├── schemas/                     # JSON Schemas (Assertion C spec)
│   ├── batch_envelope.schema.json
│   ├── challenge_request.schema.json
│   └── challenge_response.schema.json
├── tests/
│   ├── vectors/                 # RFC test vectors
│   │   ├── rfc6962_merkle.json
│   │   ├── rfc8032_ed25519.json
│   │   └── rfc3161_tsa.json
│   ├── fixtures/                # PoC sample data
│   │   ├── sample_batch.json
│   │   └── sample_challenge_request.json
│   ├── unit/
│   └── integration/
├── docs/
│   ├── api/
│   ├── architecture/
│   ├── regulatory/
│   └── world-first/
├── examples/
├── config/
├── SECURITY.md                  # Threat model & data handling
└── README.md
```

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=vcp_supervision --cov-report=html

# Run specific test categories
pytest tests/unit/
pytest tests/integration/
```

## Configuration

Configuration is managed via YAML files in the `config/` directory:

```yaml
# config/default.yaml
verification:
  signature:
    algorithm: "Ed25519"
    require_manifest: true
  merkle:
    hash_algorithm: "SHA-256"
    rfc6962_compliant: true
  timing:
    default_jurisdiction: "EU"
    hft_precision_us: 100
    non_hft_precision_ms: 1

reporting:
  dora:
    initial_report_target_hours: 4
    intermediate_report_hours: 72
  fca:
    submission_deadline_days: 14

dashboard:
  host: "0.0.0.0"
  port: 8080
  refresh_interval_seconds: 5
```

## API Reference

See [docs/api/](docs/api/) for detailed API documentation.

### Key Classes

- `SupervisionNode`: Main entry point for verification operations
- `VerificationEngine`: Core verification logic
- `SignatureVerifier`: Ed25519 signature verification
- `MerkleVerifier`: RFC 6962 Merkle proof verification
- `AnchorVerifier`: Incomplete TSA/blockchain anchor checks; see current scope above
- `TimingVerifier`: Timestamp precision and clock sync verification
- `DORAReporter`: DORA-aligned data preparation
- `ComplianceDashboard`: Web-based visualization

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone and install dev dependencies
git clone https://github.com/veritaschain/vcp-supervision-node-poc.git
cd vcp-supervision-node-poc
pip install -e ".[dev]"

# Run linting
ruff check src/
mypy src/

# Run tests
pytest
```

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Related Projects

- [VCP Specification](https://github.com/veritaschain/vcp-spec) - VeritasChain Protocol specification
- [VCP SDK](https://github.com/veritaschain/vcp-sdk) - SDK for VCP implementation
- [VCP Explorer](https://github.com/veritaschain/vcp-explorer) - Web-based VCP event explorer

## References

### Primary Regulatory Sources

- [EU RTS 25 (Regulation 2017/574)](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32017R0574)
- [EU DORA (Regulation 2022/2554)](https://eur-lex.europa.eu/eli/reg/2022/2554/oj)
- [EU AI Act (Regulation 2024/1689)](https://eur-lex.europa.eu/eli/reg/2024/1689/oj)
- [SEC Rule 17a-4](https://www.sec.gov/files/rules/final/2022/34-96034.pdf)
- [CAT NMS Plan](https://www.catnmsplan.com/)

### Technical Standards

- [RFC 6962 - Certificate Transparency](https://datatracker.ietf.org/doc/html/rfc6962)
- [RFC 3161 - Time-Stamp Protocol](https://datatracker.ietf.org/doc/html/rfc3161)
- [RFC 8032 - Edwards-Curve Digital Signature Algorithm (EdDSA)](https://datatracker.ietf.org/doc/html/rfc8032)

## Contact

**VeritasChain Standards Organization (VSO)**  
- Email: info@veritaschain.org
- Website: https://veritaschain.org
- GitHub: https://github.com/veritaschain

---

*"Verify, Don't Trust" — AI's Flight Recorder*
