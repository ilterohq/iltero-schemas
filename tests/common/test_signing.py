"""The ES256 signature form and the signed bytes every signed document of the contract shares."""

from __future__ import annotations

import pytest

from iltero_schemas.signing import (
    BUNDLE_SIGNING_SCOPE,
    P256_ORDER,
    SCANNER_CHECK_MAPPING_SIGNING_SCOPE,
    SignatureError,
    base64url,
    check_low_s,
    from_base64url,
    normalized_signature,
    r_and_s,
    signing_input,
)

# A signature whose r is 1 and whose s is 2: in range, and in its low-S form.
LOW = (1).to_bytes(32, "big") + (2).to_bytes(32, "big")


def test_a_signature_is_read_back_only_from_the_one_base64url_spelling_this_package_writes() -> None:
    written = base64url(LOW).decode("ascii")
    assert from_base64url(written) == LOW
    # 64 bytes leave four spare bits in the last character: flipping one spells the same bytes another way.
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    other = written[:-1] + alphabet[alphabet.index(written[-1]) ^ 1]
    with pytest.raises(SignatureError, match="its one base64url spelling"):
        from_base64url(other)
    with pytest.raises(SignatureError, match="its one base64url spelling"):
        from_base64url(written + "==")
    with pytest.raises(SignatureError, match="base64url text with no padding"):
        from_base64url("A")


def test_two_scopes_never_sign_the_same_bytes() -> None:
    payload = {"digest": "sha256:" + "0" * 64}
    assert signing_input(key_id="k1", scope=BUNDLE_SIGNING_SCOPE, payload=payload) != signing_input(
        key_id="k1", scope=SCANNER_CHECK_MAPPING_SIGNING_SCOPE, payload=payload
    )


def test_a_signature_is_64_bytes_with_r_and_s_inside_the_curve_order() -> None:
    assert r_and_s(LOW) == (1, 2)
    with pytest.raises(SignatureError, match="64 bytes"):
        r_and_s(LOW[:-1])
    with pytest.raises(SignatureError, match="between 0 and the curve order"):
        r_and_s(LOW[:32] + P256_ORDER.to_bytes(32, "big"))


def test_only_the_low_s_form_is_accepted_and_normalizing_gives_it() -> None:
    high = LOW[:32] + (P256_ORDER - 2).to_bytes(32, "big")
    check_low_s(LOW)
    with pytest.raises(SignatureError, match="low-S form"):
        check_low_s(high)
    assert normalized_signature(high) == LOW
