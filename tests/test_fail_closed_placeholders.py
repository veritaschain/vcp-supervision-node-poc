"""Security regressions: unimplemented proof/auth paths must never succeed."""
import asyncio

import pytest
from fastapi import HTTPException

from vcp_supervision.api.auth import JWTAuth, MTLSAuth
from vcp_supervision.verification.anchor import AnchorVerifier


class FakeRequest:
    def __init__(self, headers):
        self.headers = headers


@pytest.mark.parametrize("token", ["anything", "a.b.c", ""])
def test_jwt_placeholder_denies_any_bearer(token):
    request = FakeRequest({"Authorization": "Bearer " + token})
    with pytest.raises(HTTPException) as exc:
        asyncio.run(JWTAuth().authenticate(request))
    assert exc.value.status_code in (401, 403, 501)


def test_mtls_header_is_not_proof():
    request = FakeRequest({"X-Client-Cert-DN": "CN=arbitrary"})
    with pytest.raises(HTTPException) as exc:
        asyncio.run(MTLSAuth().authenticate(request))
    assert exc.value.status_code in (401, 403, 501)


@pytest.mark.parametrize("token", ["YQ==", "not-base64", ""])
def test_tsa_placeholder_never_passes(sample_anchor, token):
    sample_anchor.tsa_anchor.token = token
    sample_anchor.tsa_anchor.is_eidas_qualified = True
    verifier = AnchorVerifier()
    try:
        result = verifier.verify(sample_anchor.merkle_root, sample_anchor)
    finally:
        verifier.close()
    assert result["status"] != "PASSED"
    assert result["has_legal_presumption"] is False
