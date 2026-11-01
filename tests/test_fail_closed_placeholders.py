"""Security regressions: unimplemented proof/auth paths must never succeed."""
import asyncio
from types import SimpleNamespace

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


def test_tsa_placeholder_never_passes():
    tsa = SimpleNamespace(tsa_url="https://timestamp.digicert.com", token="YQ==")
    anchor = SimpleNamespace(tsa_anchor=tsa)
    verifier = AnchorVerifier()
    try:
        result = verifier._verify_tsa_anchor(b"not-a-real-root", anchor)
    finally:
        verifier._http_client.close()
    assert result["status"] != "PASSED"
    assert result["legal_presumption"] is False
