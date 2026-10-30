# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial PoC implementation
- Signature verification (Ed25519, RFC 8032)
- Merkle proof verification (RFC 6962)
- External anchor verification (TSA/Blockchain)
- Timing requirements verification (9 jurisdictions)
- DORA incident reporting support
- Compliance report generation
- Multi-jurisdiction compliance checking

### Regulatory Coverage
- EU: MiFID II, RTS 25, DORA, AI Act, eIDAS
- UK: UK MiFID II, PS21/3, FCA MAR 7A
- US: SEC Rule 17a-4, CAT NMS, Regulation SCI
- Japan: FIEA, Cabinet Office Ordinance 338
- Singapore: MAS TRM Guidelines
- Hong Kong: SFC Electronic Trading Guidelines
- Australia: ASIC Market Integrity Rules
- Canada: NI 23-103, UMIR
- Switzerland: FINMA Circular 2013/8

## [0.1.0] - 2026-01-26

### Added
- Initial release of VCP Supervision Node PoC
- Core verification engine with modular architecture
- `SupervisionNode` main class for regulatory verification
- `VerificationEngine` orchestrating all verification components
- `SignatureVerifier` for Ed25519 signature verification
- `MerkleVerifier` for RFC 6962 Merkle proof verification
- `AnchorVerifier` for TSA and blockchain anchor verification
- `TimingVerifier` for multi-jurisdiction timing compliance
- `DORAReporter` for DORA incident reporting support
- Data models aligned with VCP v1.1 specification
- Configuration via YAML files
- Comprehensive unit tests
- GitHub Actions CI/CD pipeline
- Apache 2.0 license

### Technical Standards
- RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)
- RFC 6962: Certificate Transparency (Merkle Trees)
- RFC 3161: Time-Stamp Protocol
- VCP v1.1: VeritasChain Protocol specification

### Documentation
- README with quick start guide
- Contributing guidelines
- Regulatory mapping documentation
- API documentation structure

---

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 0.1.0 | 2026-01-26 | Initial PoC release |

## Upgrade Notes

### Migrating to 0.1.0

This is the initial release. No migration required.

## Deprecation Notices

None.

---

[Unreleased]: https://github.com/veritaschain/vcp-supervision-poc/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/veritaschain/vcp-supervision-poc/releases/tag/v0.1.0
