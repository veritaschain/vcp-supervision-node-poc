# Contributing to VCP Supervision Node

Thank you for your interest in contributing to the VCP Supervision Node project! This document provides guidelines and information for contributors.

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](https://github.com/veritaschain/.github/blob/main/CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How to Contribute

### Reporting Issues

Before creating an issue, please check existing issues to avoid duplicates. When reporting:

1. **Bug Reports**: Include Python version, OS, error messages, and minimal reproduction steps
2. **Feature Requests**: Describe the use case and expected behavior
3. **Regulatory Questions**: Reference specific regulations with article numbers

### Pull Requests

1. Fork the repository and create a branch from `main`
2. Follow the coding standards below
3. Add tests for new functionality
4. Update documentation as needed
5. Ensure all tests pass: `pytest`
6. Submit a PR with a clear description

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/vcp-supervision-poc.git
cd vcp-supervision-poc

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

## Coding Standards

### Python Style

- Follow [PEP 8](https://pep8.org/) with 100 character line limit
- Use type hints for all function signatures
- Use `ruff` for linting: `ruff check src/`
- Use `mypy` for type checking: `mypy src/`

### Documentation

- Use Google-style docstrings
- Include regulatory references where applicable
- Keep README.md and docs/ in sync

### Example Docstring

```python
def verify_event(
    self,
    event: VCPEvent,
    proof: MerkleProof,
    anchor: AnchorRecord,
    jurisdiction: str | None = None,
) -> VerificationResult:
    """
    Verify a single VCP event with its Merkle proof and anchor.

    This method performs comprehensive verification including signature,
    Merkle inclusion, external anchor, and timing compliance checks.

    Args:
        event: The VCP event to verify
        proof: Merkle inclusion proof for the event
        anchor: External anchor record (TSA/Blockchain)
        jurisdiction: Target jurisdiction code (default: config default)

    Returns:
        VerificationResult with status, compliance score, and details

    Raises:
        ValueError: If proof format is invalid

    Regulatory Alignment:
        - SEC Rule 17a-4: Audit trail integrity
        - EU RTS 25: Timestamp precision requirements
        - eIDAS Article 42: Qualified timestamps

    Example:
        >>> result = engine.verify_event(event, proof, anchor, jurisdiction="EU")
        >>> print(f"Status: {result.status}, Score: {result.compliance_score}")
    """
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add DORA incident classification support
fix: correct Merkle proof direction validation
docs: update regulatory mapping for UK PS21/3
test: add integration tests for TSA verification
refactor: simplify timing verifier jurisdiction logic
```

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=vcp_supervision --cov-report=html

# Run specific test file
pytest tests/unit/test_verification.py

# Run tests matching pattern
pytest -k "test_merkle"

# Run slow tests (marked)
pytest -m slow
```

### Writing Tests

- Place unit tests in `tests/unit/`
- Place integration tests in `tests/integration/`
- Use fixtures for common test data
- Test both success and failure cases
- Include regulatory compliance test scenarios

## Regulatory Considerations

When contributing features related to regulatory compliance:

1. **Reference Primary Sources**: Always cite specific regulation articles
2. **Evidence Grade**: Classify regulatory references (Primary Law, RTS, Guidance)
3. **Jurisdictional Differences**: Document any jurisdiction-specific behavior
4. **Caveats**: Note when requirements are subject to interpretation

### Evidence Grade Classification

| Grade | Description | Example |
|-------|-------------|---------|
| Primary Law | EU Regulations, national laws | MiFID II, FIEA |
| RTS/ITS | Delegated regulations | EU RTS 25 |
| Regulator Rule | FCA Handbook, SEC Rules | FCA MAR 7A |
| Regulator Guidance | Supervisory guidance | MAS TRM |
| SRO Rule | Self-regulatory organization | FINRA Rules |

## Architecture Guidelines

### Adding New Verifiers

1. Create module in `src/vcp_supervision/verification/`
2. Implement verification logic with clear error codes
3. Add to `VerificationEngine` orchestration
4. Update models if new data structures needed
5. Add comprehensive tests

### Adding New Jurisdictions

1. Add requirements to `TimingVerifier.REQUIREMENTS`
2. Document regulatory references
3. Add compliance report regulations mapping
4. Update README jurisdiction table
5. Add jurisdiction-specific tests

## Release Process

1. Update `CHANGELOG.md` with changes
2. Bump version in `pyproject.toml` and `__init__.py`
3. Create release PR targeting `main`
4. After merge, tag release: `git tag v0.1.0`
5. Push tag: `git push origin v0.1.0`
6. GitHub Actions will publish to PyPI

## Questions?

- Open a [Discussion](https://github.com/veritaschain/vcp-supervision-poc/discussions)
- Email: technical@veritaschain.org

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
