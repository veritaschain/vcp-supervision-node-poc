"""Synthetic key-admission regressions; historical signed fixtures stay intact."""

import base64
import hashlib

import pytest

from vcp_supervision.verification.signature import SignatureVerifier


P = 2**255 - 19
SMALL_ORDER_KEYS = (
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
)


def noncanonical_keys():
    # All 19 out-of-field y values, both signs, plus the two x=0 sign aliases.
    for y in range(P, 2**255):
        for sign in (0, 1):
            yield (y | (sign << 255)).to_bytes(32, "little")
    for y in (1, P - 1):
        yield (y | (1 << 255)).to_bytes(32, "little")


def configure_key(event, manifest, raw):
    encoded = base64.b64encode(raw).decode("ascii")
    fingerprint = hashlib.sha256(raw).hexdigest()
    entry = next(iter(manifest.authorized_keys.values()))
    entry.fingerprint = fingerprint
    entry.public_key = encoded
    manifest.authorized_keys = {fingerprint: entry}
    event.signature.public_key = encoded
    event.signature.value = base64.b64encode(b"\x01" + bytes(63)).decode("ascii")


@pytest.mark.parametrize("key_hex", SMALL_ORDER_KEYS)
def test_manifest_cannot_authorize_a_small_order_key(
    sample_vcp_event, public_key_manifest, key_hex
):
    configure_key(sample_vcp_event, public_key_manifest, bytes.fromhex(key_hex))
    result = SignatureVerifier(public_key_manifest).verify(sample_vcp_event)
    assert result["status"] == "FAILED"
    assert result["error_code"] == "KEY_INVALID"
    assert "small-order" in result["message"]
    assert result.get("signature_math_valid") is not True


@pytest.mark.parametrize("raw", list(noncanonical_keys()))
def test_noncanonical_key_cannot_bypass_admission(
    sample_vcp_event, public_key_manifest, raw
):
    configure_key(sample_vcp_event, public_key_manifest, raw)
    result = SignatureVerifier(public_key_manifest).verify(sample_vcp_event)
    assert result["status"] == "FAILED"
    assert result["error_code"] == "KEY_INVALID"
    assert "noncanonical" in result["message"]


@pytest.mark.parametrize("mode", ["authorized", "missing_manifest", "math_only"])
def test_identity_forgery_cannot_pass_after_payload_changes(
    sample_vcp_event, public_key_manifest, mode
):
    configure_key(sample_vcp_event, public_key_manifest, b"\x01" + bytes(31))
    verifier = SignatureVerifier(
        None if mode == "missing_manifest" else public_key_manifest,
        require_manifest=mode != "math_only",
    )
    for quantity in (1000, 999999):
        sample_vcp_event.payload["quantity"] = quantity
        result = verifier.verify(sample_vcp_event)
        assert result["status"] == "FAILED"
        assert result["error_code"] == "KEY_INVALID"
        assert result.get("signature_math_valid") is not True


def test_valid_signatures_and_original_authorization_scope_are_preserved(
    sample_vcp_event, public_key_manifest
):
    assert SignatureVerifier(public_key_manifest).verify(sample_vcp_event)["status"] == "PASSED"
    for verifier in (SignatureVerifier(), SignatureVerifier(require_manifest=False)):
        result = verifier.verify(sample_vcp_event)
        assert result["status"] == "INDETERMINATE"
        assert result["signature_math_valid"] is True
    sample_vcp_event.payload["quantity"] += 1
    result = SignatureVerifier(public_key_manifest).verify(sample_vcp_event)
    assert result["status"] == "FAILED"
    assert result["error_code"] == "SIG_INVALID"
