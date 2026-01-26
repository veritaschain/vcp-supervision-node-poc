# Regulatory Mapping for VCP Supervision Node

This document maps regulatory requirements to VCP Supervision Node capabilities across 10 jurisdictions.

## Document Information

| Field | Value |
|-------|-------|
| Document ID | VSO-POC-REGMAP-001 |
| Version | 1.0 |
| Date | January 2026 |
| Status | Reference Document |

## Evidence Grade Classification

All regulatory references are classified by evidence strength:

| Grade | Description | Authority Level |
|-------|-------------|-----------------|
| **Primary Law** | EU Regulations, national laws | Highest legal authority |
| **RTS/ITS** | Delegated/implementing regulations | Legal binding force |
| **Regulator Rule** | FCA Handbook, SEC Rules | Regulatory authority |
| **Regulator Guidance** | Supervisory guidance | Soft law / best practice |
| **SRO Rule** | Self-regulatory organization rules | Industry standard |

---

## 1. Timestamp Precision Requirements

### 1.1 Jurisdiction Comparison

| Jurisdiction | HFT Precision | Non-HFT Precision | UTC Sync | Evidence Grade | Regulation |
|-------------|---------------|-------------------|----------|----------------|------------|
| **EU** | 100µs | 1ms | Required | Primary Law (RTS) | RTS 25 Art.1-4 |
| **UK** | 100µs | 1ms | Required | Primary Law | UK RTS 25 |
| **US (Exchange)** | 100µs | - | NIST | Primary Law | CAT NMS Plan |
| **US (BD)** | - | 50ms | NIST | Primary Law | FINRA Rule 4590 |
| **Japan** | ms (recommended) | ms (recommended) | NICT | Regulator Guidance | FIEA Guidelines |
| **Singapore** | - | 1 second | Recommended | Regulator Guidance | MAS TRM |
| **Hong Kong** | µs | ms | Recommended | Regulator Guidance | SFC Guidelines |
| **Australia** | RTS 25 aligned | ms | UTC | Primary Law | ASIC MIR |
| **Canada** | 50ms | ms | Required | Primary Law | UMIR 10.14 |
| **Switzerland** | MiFID-like | ms | Required | Regulator Guidance | FINMA 2013/8 |

### 1.2 VCP Implementation

```
ClockSyncStatus Mapping:
├── PTP_LOCKED    → <1µs accuracy  → EU/UK HFT compliant
├── NTP_SYNCED    → <1ms accuracy  → EU/UK Non-HFT compliant
├── BEST_EFFORT   → Variable       → Warning for regulated entities
└── UNRELIABLE    → Unknown        → Rejected for all jurisdictions
```

### 1.3 Primary Source URLs

- EU RTS 25: https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32017R0574
- CAT NMS: https://www.catnmsplan.com/sites/default/files/2020-07/CAT-NMS-Plan-as-of-July-2020.pdf
- FINRA 4590: https://www.finra.org/rules-guidance/rulebooks/finra-rules/4590

---

## 2. Audit Trail Integrity Requirements

### 2.1 Jurisdiction Comparison

| Jurisdiction | Immutability | Audit Trail | Retention | Evidence Grade | Regulation |
|-------------|--------------|-------------|-----------|----------------|------------|
| **EU** | Required | Required | 5 years | Primary Law | MiFID II Art.17 |
| **EU (AI)** | Required | Required | 10 years | Primary Law | AI Act Art.18 |
| **UK** | Required | Required | 5-7 years | Primary Law | UK MiFID II |
| **US** | WORM or Audit Trail | Required | 6 years | Primary Law | SEC 17a-4 |
| **Japan** | Required | Required | 7-10 years | Primary Law | FIEA, Companies Act |
| **Singapore** | Required | Required | 5 years | Regulator Guidance | MAS TRM |
| **Hong Kong** | Required | Required | 7 years | Regulator Guidance | SFC Guidelines |
| **Australia** | Required | Required | 7 years | Primary Law | ASIC MIR |
| **Canada** | Required | Required | 7 years | Primary Law | NI 23-103 |
| **Switzerland** | Required | Required | 5-10 years | Regulator Guidance | FINMA 2013/8 |

### 2.2 SEC Rule 17a-4 (2022 Amendment)

**Critical Update**: The 2022 amendment (Release 34-94382) explicitly permits audit trail alternatives to WORM:

> "The rule permits broker-dealers to preserve required records electronically using either write once, read many (WORM) technology or an audit trail alternative."

**Audit Trail Requirements (17a-4(f)(2)(ii)(A))**:
- Timestamp all changes and deletions
- Preserve original record content
- Enable reconstruction of the original record

**VCP Alignment**: Merkle Tree + External Anchor architecture satisfies these requirements.

### 2.3 VCP Implementation

```
Integrity Verification:
├── Signature (Ed25519)     → Per-event authenticity
├── Merkle Tree (RFC 6962)  → Batch integrity
├── External Anchor         → Independent timestamp
│   ├── TSA (RFC 3161)      → Legal presumption (eIDAS)
│   └── Blockchain          → Decentralized proof
└── Hash Chain              → Sequential integrity
```

### 2.4 Primary Source URLs

- SEC 17a-4 (2022): https://www.sec.gov/rules/final/2022/34-94382.pdf
- eIDAS Art.42: https://eur-lex.europa.eu/eli/reg/2014/910/oj

---

## 3. Incident Reporting Requirements

### 3.1 Jurisdiction Comparison

| Jurisdiction | Initial Report | Intermediate | Final | Evidence Grade | Regulation |
|-------------|----------------|--------------|-------|----------------|------------|
| **EU (DORA)** | ~4 hours* | 72 hours | 1 month | Primary Law + RTS | DORA Art.19-23 |
| **UK** | 72 hours | As needed | Resolution+30d | Regulator Guidance | PS21/3 |
| **US (Reg SCI)** | Immediate | 24 hours | 30 days | Primary Law | Regulation SCI |
| **Singapore** | Hours | Ongoing | 30 days | Regulator Guidance | MAS TRM |
| **Australia** | 72 hours | Ongoing | Post-event | Primary Law | ASIC MIR |

*Note: DORA timeframes are operational targets based on ESAs RTS/ITS. The framework is established in DORA Articles 19-23, with specific timeframes detailed in implementing measures.

### 3.2 DORA Framework Structure

```
DORA Incident Reporting:
├── Framework (Primary Law)
│   ├── Article 19: Classification criteria
│   ├── Article 20: Reporting obligations
│   ├── Article 21: Content harmonisation
│   ├── Article 22: Centralisation
│   └── Article 23: Feedback mechanism
│
└── Details (RTS/ITS)
    ├── Taxonomy
    ├── Timeframes (~4h/72h/1m)
    ├── Templates
    └── Submission procedures
```

### 3.3 VCP Implementation

```python
# DORAReporter operational targets (based on RTS/ITS)
INITIAL_REPORT_TARGET_HOURS = 4      # After classification
INTERMEDIATE_REPORT_HOURS = 72       # Updates
FINAL_REPORT_DAYS = 30               # After resolution
```

### 3.4 Primary Source URLs

- DORA: https://eur-lex.europa.eu/eli/reg/2022/2554/oj
- EBA DORA RTS: https://www.eba.europa.eu/activities/single-rulebook/regulatory-activities/operational-resilience
- UK PS21/3: https://www.bankofengland.co.uk/prudential-regulation/publication/2021/march/operational-resilience-of-fmis-policy-statement
- Regulation SCI: https://www.sec.gov/rules/final/2014/34-73639.pdf

---

## 4. On-Demand Submission Requirements

### 4.1 Jurisdiction Comparison

| Jurisdiction | Deadline | Content | Evidence Grade | Regulation |
|-------------|----------|---------|----------------|------------|
| **UK (FCA)** | 14 days | Evidence package | Regulator Rule | MAR 7A.3.9R |
| **EU** | Reasonable time | Complete records | Primary Law | MiFID II Art.25 |
| **US** | Upon request | Full audit trail | Primary Law | SEC 17a-4 |
| **Japan** | Upon request | Program details | Primary Law | FIEA |

### 4.2 VCP Implementation

VCP Merkle proof generation enables immediate evidence package creation:

```
Evidence Package Contents:
├── VCP Events (relevant period)
├── Merkle Proofs (inclusion)
├── Anchor Records (TSA/BC)
├── Public Key Manifest
└── Verification Report (PDF/JSON)
```

### 4.3 Primary Source URLs

- FCA MAR 7A: https://www.handbook.fca.org.uk/handbook/MAR/7A

---

## 5. EU AI Act Requirements

### 5.1 Article Mapping

| Article | Requirement | VCP Component | Evidence Grade |
|---------|-------------|---------------|----------------|
| **Art.12** | Logging capability | VCP Event Chain | Primary Law |
| **Art.14** | Human oversight | HUMAN_OVERRIDE event | Primary Law |
| **Art.18** | Documentation (10 years) | AnchorRecord persistence | Primary Law |

### 5.2 Article 12 vs Article 18 Distinction

**Article 12 (Record-keeping)**:
- Automatic event logging capability
- Traceability of AI system operation
- Runtime monitoring

**Article 18 (Documentation keeping)**:
- Technical documentation retention
- 10-year availability to authorities
- Post-market obligations

### 5.3 VCP Implementation

```
AI Act Compliance:
├── Article 12: Logging Capability
│   └── VCP Event automatic generation
│
├── Article 14: Human Oversight
│   └── HUMAN_OVERRIDE event type
│
└── Article 18: 10-Year Retention
    └── External anchor with long-term storage
```

### 5.4 Primary Source URLs

- EU AI Act: https://eur-lex.europa.eu/eli/reg/2024/1689/oj

---

## 6. Qualified Timestamps (eIDAS)

### 6.1 Legal Framework

| Element | Requirement | VCP Component |
|---------|-------------|---------------|
| **Article 41** | Legal effect | TSA anchor |
| **Article 42** | Qualified timestamp | eIDAS-qualified TSA |
| **Presumption** | Accuracy of date/time | TSAAnchor.is_eidas_qualified |

### 6.2 Legal Presumption

eIDAS Article 41(2):
> "A qualified electronic time stamp shall enjoy the presumption of the accuracy of the date and the time it indicates and the integrity of the data to which the date and time are bound."

### 6.3 VCP Implementation

```python
class TSAAnchor:
    is_eidas_qualified: bool  # Legal presumption flag
    
# Verification returns legal_presumption status
result = {
    "is_eidas_qualified": True,
    "legal_presumption": True  # eIDAS Art.41
}
```

### 6.4 Primary Source URLs

- eIDAS: https://eur-lex.europa.eu/eli/reg/2014/910/oj

---

## 7. Verification Component Mapping

### 7.1 Regulatory Alignment Matrix

| VCP Component | SEC 17a-4 | MiFID II | DORA | RTS 25 | AI Act | eIDAS |
|--------------|-----------|----------|------|--------|--------|-------|
| **SignatureVerifier** | ✓ | ✓ | ✓ | - | ✓ | ✓ |
| **MerkleVerifier** | ✓ | ✓ | ✓ | - | ✓ | - |
| **AnchorVerifier** | ✓ | - | ✓ | - | ✓ | ✓ |
| **TimingVerifier** | - | ✓ | - | ✓ | - | - |
| **DORAReporter** | - | - | ✓ | - | - | - |

### 7.2 Verification Flow

```
Input: VCPEvent + MerkleProof + AnchorRecord
         │
         ▼
┌─────────────────────────────────────────┐
│        VerificationEngine               │
├─────────────────────────────────────────┤
│  1. SignatureVerifier.verify()          │ → SEC 17a-4, eIDAS
│  2. MerkleVerifier.verify()             │ → SEC 17a-4, MiFID II
│  3. AnchorVerifier.verify()             │ → eIDAS Art.42, DORA
│  4. TimingVerifier.verify()             │ → RTS 25, CAT
└─────────────────────────────────────────┘
         │
         ▼
Output: VerificationResult
        ├── status: PASSED/FAILED/WARNING
        ├── compliance_score: 0.0-1.0
        └── details: {per-component results}
```

---

## 8. Ambiguous Areas and Interpretations

### 8.1 Areas Requiring Clarification

| Area | Ambiguity | Jurisdictions | Recommendation |
|------|-----------|---------------|----------------|
| HFT Definition | Criteria vary | EU, JP, US | Document entity classification |
| Timestamp Application Point | "Accurate point" unspecified | EU | Follow ESMA Q&A guidance |
| Audit Trail "Sufficient Info" | Fields unspecified | US | Preserve all original content |
| AI Act Trading Algo Scope | Annex III unclear | EU | Monitor EC FAQ updates |
| DORA Third-Party ICT | Supervision node status | EU | Clarify with NCA |
| Japan Program Details | Source code vs parameters | JP | Consult FSA guidance |

### 8.2 Pending Regulatory Developments

| Development | Expected | Impact |
|-------------|----------|--------|
| DORA RTS/ITS Final | Published | Timeframe confirmation |
| UK PS21/3 Full Application | 2025-03-31 | 72h deadline active |
| AI Act High-Risk Application | 2026-08-02 | Art.12 enforcement |
| ASIC CP386 Final | 2026-03 | AI-specific requirements |

---

## 9. References

### 9.1 EU Regulations

1. MiFID II (2014/65/EU): https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32014L0065
2. RTS 25 (2017/574): https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32017R0574
3. RTS 6 (2017/589): https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32017R0589
4. DORA (2022/2554): https://eur-lex.europa.eu/eli/reg/2022/2554/oj
5. AI Act (2024/1689): https://eur-lex.europa.eu/eli/reg/2024/1689/oj
6. MAR (596/2014): https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32014R0596
7. eIDAS (910/2014): https://eur-lex.europa.eu/eli/reg/2014/910/oj
8. GDPR (2016/679): https://eur-lex.europa.eu/eli/reg/2016/679/oj

### 9.2 UK Regulations

9. UK MiFID II: https://www.legislation.gov.uk/uksi/2018/1149/contents/made
10. FCA SYSC 18: https://www.handbook.fca.org.uk/handbook/SYSC/18
11. FCA MAR 7A: https://www.handbook.fca.org.uk/handbook/MAR/7A
12. PS21/3: https://www.bankofengland.co.uk/prudential-regulation/publication/2021/march/operational-resilience-of-fmis-policy-statement

### 9.3 US Regulations

13. SEC Rule 17a-4: https://www.sec.gov/rules/final/2022/34-94382.pdf
14. CAT NMS Plan: https://www.catnmsplan.com/
15. Regulation SCI: https://www.sec.gov/rules/final/2014/34-73639.pdf
16. FINRA Rule 3110: https://www.finra.org/rules-guidance/rulebooks/finra-rules/3110
17. FINRA Rule 4590: https://www.finra.org/rules-guidance/rulebooks/finra-rules/4590
18. CFTC Rule 1.31: https://www.cftc.gov/sites/default/files/idc/groups/public/@lrfederalregister/documents/file/2017-05200a.pdf

### 9.4 Other Jurisdictions

19. Japan FIEA: https://www.fsa.go.jp/common/law/fie01.pdf
20. MAS TRM: https://www.mas.gov.sg/-/media/mas/regulations-and-financial-stability/regulations-guidance-and-licensing/cross-sector/technology-risk-management/guidelines-on-risk-management-practices---technology-risk.pdf
21. SFC Guidelines: https://www.sfc.hk/-/media/EN/files/ER/PDF/Guidelines-on-Electronic-Trading.pdf
22. ASIC MIR: https://download.asic.gov.au/media/1344732/mir-securities-20100501.pdf
23. CSA NI 23-103: https://www.osc.ca/sites/default/files/pdfs/irps/ni_20121213_23-103_electronic-trading-dea.pdf
24. FINMA 2013/8: https://www.finma.ch/en/~/media/finma/dokumente/dokumentencenter/myfinma/rundschreiben/finma-rs-2013-08.pdf

### 9.5 Technical Standards

25. RFC 8032 (EdDSA): https://datatracker.ietf.org/doc/html/rfc8032
26. RFC 6962 (CT): https://datatracker.ietf.org/doc/html/rfc6962
27. RFC 3161 (TSP): https://datatracker.ietf.org/doc/html/rfc3161
28. NIST SP 800-53: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-26 | Initial regulatory mapping |

---

**VeritasChain Standards Organization**  
info@veritaschain.org | https://veritaschain.org

*"Verify, Don't Trust"*
