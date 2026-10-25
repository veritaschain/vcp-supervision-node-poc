# Security Policy

**Document ID:** VSO-SEC-POC-001  
**Version:** 1.0  
**Last Updated:** January 2026

---

## Reporting Security Vulnerabilities

**DO NOT** create public GitHub issues for security vulnerabilities.

Please report security issues to: **security@veritaschain.org**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested remediation (if any)

We aim to acknowledge reports within 48 hours and provide a detailed response within 7 days.

---

## Threat Model

### 1. Assets Under Protection

| Asset | Sensitivity | Protection Goal |
|-------|-------------|-----------------|
| VCP Event Data | High | Integrity, Confidentiality |
| Merkle Roots | Critical | Integrity |
| Private Keys (Firm-side) | Critical | Out of scope (not stored) |
| Public Key Manifests | Medium | Integrity, Availability |
| TSA Tokens | High | Integrity |
| Blockchain Anchor References | Medium | Integrity |
| Compliance Reports | High | Integrity, Confidentiality |
| Configuration Files | Medium | Integrity |

### 2. Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         UNTRUSTED ZONE                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                      │
│  │  Firm A     │  │  Firm B     │  │  Firm C     │                      │
│  │  (Submitter)│  │  (Submitter)│  │  (Submitter)│                      │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                      │
│         │                │                │                              │
│         └────────────────┼────────────────┘                              │
│                          │                                               │
│                          ▼                                               │
├─────────────────────────────────────────────────────────────────────────┤
│                       TRUST BOUNDARY                                     │
├─────────────────────────────────────────────────────────────────────────┤
│                          │                                               │
│                          ▼                                               │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                  VCP SUPERVISION NODE                            │    │
│  │  ┌─────────────────────────────────────────────────────────┐    │    │
│  │  │  Input Validation Layer                                  │    │    │
│  │  │  - Schema validation                                     │    │    │
│  │  │  - Size limits                                           │    │    │
│  │  │  - Sanitization                                          │    │    │
│  │  └─────────────────────────────────────────────────────────┘    │    │
│  │                          │                                       │    │
│  │                          ▼                                       │    │
│  │  ┌─────────────────────────────────────────────────────────┐    │    │
│  │  │  Verification Engine (TRUSTED)                          │    │    │
│  │  │  - Cryptographic operations                              │    │    │
│  │  │  - No external network calls during verification         │    │    │
│  │  └─────────────────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                          │                                               │
│                          ▼                                               │
├─────────────────────────────────────────────────────────────────────────┤
│                       TRUST BOUNDARY                                     │
├─────────────────────────────────────────────────────────────────────────┤
│                          │                                               │
│  ┌───────────────────────┼───────────────────────┐                      │
│  │                       ▼                       │                      │
│  │  ┌─────────────┐  ┌─────────────────────┐    │  SEMI-TRUSTED        │
│  │  │  TSA        │  │  Public Blockchain  │    │  (External Anchors)  │
│  │  │  (RFC 3161) │  │  (Ethereum, etc.)   │    │                      │
│  │  └─────────────┘  └─────────────────────┘    │                      │
│  └───────────────────────────────────────────────┘                      │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3. Threat Categories

#### 3.1 Data Integrity Threats

| Threat ID | Threat | Attack Vector | Mitigation |
|-----------|--------|---------------|------------|
| T-INT-01 | **Merkle Root Tampering** | Attacker modifies submitted Merkle root | TSA/Blockchain anchor verification; roots are not stored, only verified |
| T-INT-02 | **Event Payload Tampering** | Attacker modifies event content after signing | Ed25519 signature verification |
| T-INT-03 | **Inclusion Proof Forgery** | Attacker submits false Merkle proof | RFC 6962 proof verification against anchored root |
| T-INT-04 | **Timestamp Manipulation** | Attacker backdates/postdates events | External TSA verification; clock sync status check |
| T-INT-05 | **Sequence Number Manipulation** | Attacker reorders or omits events | Hash chain (prev_hash) verification; completeness detection |

#### 3.2 Replay & Substitution Attacks

| Threat ID | Threat | Attack Vector | Mitigation |
|-----------|--------|---------------|------------|
| T-REP-01 | **Anchor Replay** | Reuse valid TSA token for different data | Verify TSA token contains correct Merkle root hash |
| T-REP-02 | **Proof Replay** | Reuse valid proof for different event | Verify event hash matches leaf in proof |
| T-REP-03 | **Cross-Firm Substitution** | Use Firm A's anchor for Firm B's data | Manifest-based key authorization; firm binding |

#### 3.3 External Anchor Threats

| Threat ID | Threat | Attack Vector | Mitigation |
|-----------|--------|---------------|------------|
| T-ANC-01 | **Fake TSA** | Attacker submits token from unauthorized TSA | Trusted TSA allowlist; eIDAS qualified TSA preference |
| T-ANC-02 | **TSA Compromise** | TSA issues fraudulent timestamps | Dual anchoring (TSA + Blockchain); multi-TSA verification |
| T-ANC-03 | **Blockchain Reorg** | Short-term chain reorganization | Require minimum confirmation count (configurable) |
| T-ANC-04 | **Blockchain RPC Compromise** | Attacker controls RPC endpoint | Multiple RPC providers; local node option |

#### 3.4 Denial of Service

| Threat ID | Threat | Attack Vector | Mitigation |
|-----------|--------|---------------|------------|
| T-DOS-01 | **Large Payload** | Submit oversized events/proofs | Input size limits; streaming validation |
| T-DOS-02 | **Proof Bomb** | Submit deeply nested Merkle proofs | Maximum proof depth limit |
| T-DOS-03 | **Batch Flood** | Submit excessive batch requests | Rate limiting; queue management |

---

## Data Handling

### 1. Personally Identifiable Information (PII)

**Policy:** The VCP Supervision Node does NOT require PII to function.

| Data Type | Required | Recommendation |
|-----------|----------|----------------|
| Trader names | No | Exclude from payload |
| Account numbers | No | Use pseudonymous identifiers |
| IP addresses | No | Do not include |
| Email addresses | No | Do not include |

**Firm Guidance:** VCP payloads should contain only:
- Order/trade identifiers (pseudonymous OK)
- Instrument identifiers (symbols)
- Quantities and prices
- Timestamps
- Algorithm identifiers

### 2. Trade-Sensitive Data

**Received Data Classification:**

| Data Element | Sensitivity | Retention in PoC |
|--------------|-------------|------------------|
| Event payloads | HIGH | Memory only during verification; not persisted |
| Merkle roots | MEDIUM | May be logged for audit trail |
| Verification results | LOW | Logged and stored |
| Compliance scores | LOW | Stored in reports |

**Storage Policy (PoC):**
- Raw event payloads are NOT persisted to disk
- Only verification results (pass/fail, scores, error codes) are stored
- Merkle roots may be cached for batch completeness checks
- All stored data can be encrypted at rest (configurable)

### 3. Data Retention

| Data Type | Default Retention | Configurable |
|-----------|-------------------|--------------|
| Verification logs | 90 days | Yes |
| Compliance reports | 7 years | Yes (regulatory alignment) |
| Alert history | 1 year | Yes |
| Performance metrics | 30 days | Yes |

---

## Key Management

### 1. Keys NOT Managed by Supervision Node

The following keys are **out of scope** for the Supervision Node:

| Key Type | Owner | Responsibility |
|----------|-------|----------------|
| Ed25519 signing keys | Firms | Firm's HSM/key management |
| TSA signing keys | TSA providers | TSA operator |
| Blockchain keys | Firms (for anchoring) | Firm's wallet management |

### 2. Keys Managed by Supervision Node

| Key Type | Purpose | Storage | Rotation |
|----------|---------|---------|----------|
| API authentication keys | Dashboard access | Environment variables | 90 days recommended |
| Encryption keys (at-rest) | Database encryption | External KMS preferred | Annual |
| TLS certificates | HTTPS for dashboard | File system or secret manager | Before expiry |

### 3. Public Key Manifest

The Supervision Node validates signatures against a **Public Key Manifest**:

```yaml
# Example manifest structure
manifest:
  version: 1
  updated_at: "2026-01-26T00:00:00Z"
  authorized_keys:
    - fingerprint: "sha256:abc123..."
      public_key: "base64-encoded-key"
      algorithm: "Ed25519"
      entity_id: "FIRM-001"
      entity_name: "Example Trading Ltd"
      valid_from: "2025-01-01T00:00:00Z"
      valid_until: null  # No expiry
      revoked: false
```

**Manifest Security:**
- Manifests should be signed by a trusted authority
- Distribution via secure channel (HTTPS, authenticated API)
- Cached locally with integrity verification
- Revocation checked on each verification

---

## Secure Configuration

### 1. Production Hardening Checklist

```yaml
# config/production.yaml

security:
  # Input validation
  max_event_size_bytes: 1048576  # 1 MB
  max_proof_depth: 64
  max_batch_size: 10000
  
  # Rate limiting
  rate_limit_requests_per_minute: 1000
  rate_limit_batch_per_minute: 100
  
  # TLS
  tls_enabled: true
  tls_min_version: "1.3"
  tls_cert_path: "/etc/vcp/tls/cert.pem"
  tls_key_path: "/etc/vcp/tls/key.pem"
  
  # Authentication
  require_authentication: true
  auth_method: "bearer"  # or "mtls" for production
  
  # Logging
  log_level: "INFO"
  log_pii: false
  log_payloads: false  # Never log raw payloads in production

verification:
  # Anchor validation
  trusted_tsa_urls:
    - "https://timestamp.digicert.com"
    - "https://freetsa.org/tsr"
  require_eidas_qualified: false  # Set true for EU production
  
  blockchain:
    min_confirmations: 12  # Higher for production
    rpc_urls:
      - "https://mainnet.infura.io/v3/YOUR_KEY"
      - "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"
```

### 2. Environment Variables

Sensitive configuration should use environment variables:

```bash
# Required
export VCP_API_KEY="your-api-key"
export VCP_DATABASE_URL="postgresql://..."

# Optional
export VCP_TSA_AUTH_TOKEN="..."
export VCP_BLOCKCHAIN_RPC_KEY="..."
export VCP_ENCRYPTION_KEY="..."  # For at-rest encryption
```

### 3. Secrets Management

**Recommended:** Use a secrets manager in production:
- AWS Secrets Manager
- HashiCorp Vault
- Azure Key Vault
- Google Secret Manager

---

## Audit Logging

### 1. Security Events Logged

| Event Type | Log Level | Details Captured |
|------------|-----------|------------------|
| Verification attempt | INFO | Event ID, result, score |
| Verification failure | WARN | Event ID, error code, reason |
| Signature failure | WARN | Event ID, key fingerprint |
| Unknown key | WARN | Key fingerprint, entity claimed |
| Anchor verification failure | WARN | Anchor type, reason |
| Rate limit exceeded | WARN | Source IP, endpoint |
| Authentication failure | WARN | Source IP, method |
| Configuration change | INFO | Changed setting, old/new value |

### 2. Log Format

```json
{
  "timestamp": "2026-01-26T12:00:00.123456Z",
  "level": "WARN",
  "event": "verification_failed",
  "event_id": "01234567-89ab-cdef-0123-456789abcdef",
  "error_code": "SIG_INVALID",
  "entity_id": "FIRM-001",
  "source_ip": "192.168.1.100",
  "request_id": "req-abc123",
  "duration_ms": 15
}
```

### 3. Log Retention

- Security logs: Minimum 1 year
- Audit logs: Minimum 7 years (regulatory alignment)
- Debug logs: 7 days (not recommended in production)

---

## Incident Response

### 1. Security Incident Categories

| Category | Example | Response Time |
|----------|---------|---------------|
| Critical | Key compromise, data breach | Immediate |
| High | Successful attack, DoS | 4 hours |
| Medium | Failed attack attempts | 24 hours |
| Low | Policy violations | 72 hours |

### 2. Incident Response Contacts

- **Security Team:** security@veritaschain.org
- **On-Call:** (Internal use only)

### 3. Disclosure Policy

- Critical vulnerabilities: Coordinated disclosure (90 days)
- High vulnerabilities: Coordinated disclosure (60 days)
- Medium/Low: Public disclosure after fix

---

## Compliance Considerations

### 1. Regulatory Alignment

| Regulation | Relevant Requirements | Status |
|------------|----------------------|--------|
| GDPR | Data minimization, right to erasure | PII not collected |
| eIDAS | Qualified timestamp requirements | TSA validation supported |
| SEC 17a-4 | Record retention (WORM or audit-trail alternative) | Anchor verification supports tamper-evidence; compliance not determined |
| MiFID II | Audit trail integrity | Merkle proof verification |
| DORA | ICT incident reporting | Reporting module support |

### 2. Penetration Testing

- Annual penetration testing recommended
- Scope: API endpoints, dashboard, verification logic
- Contact security@veritaschain.org for coordination

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | January 2026 | Initial release |

---

**VeritasChain Standards Organization (VSO)**  
security@veritaschain.org

*"Verify, Don't Trust"*
