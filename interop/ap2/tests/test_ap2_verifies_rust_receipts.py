"""Google's AP2 SDK must accept receipts signed by a2a-gov-receipt.

Vectors: testdata/rust/receipts.json, written by
`cargo run -p a2a-gov-receipt --example gen_receipt_vectors`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from ap2.sdk.generated.checkout_receipt import CheckoutReceipt
from ap2.sdk.jwt_helper import verify_jwt
from ap2.sdk.sdjwt.common import compute_sd_hash, parse_token
from jwcrypto.jwk import JWK

VECTORS = json.loads(
    (Path(__file__).resolve().parents[3] / "testdata" / "rust" / "receipts.json").read_text()
)["vectors"]


@pytest.mark.parametrize("v", VECTORS, ids=lambda v: v["expected_status"] + v["receipt"][-8:])
def test_signature_and_base_fields(v: dict[str, Any]) -> None:
    payload = verify_jwt(v["receipt"], JWK(**v["verifier_jwk"]))
    assert payload["status"] == v["expected_status"]
    assert isinstance(payload["iss"], str) and isinstance(payload["iat"], int)


@pytest.mark.parametrize("v", VECTORS, ids=lambda v: v["receipt"][-8:])
def test_reference_is_ap2s_own_sd_hash_of_the_closing_hop(v: dict[str, Any]) -> None:
    payload = verify_jwt(v["receipt"], JWK(**v["verifier_jwk"]))
    closing = v["chain"].rsplit("~~", 1)[-1]
    assert payload["reference"] == compute_sd_hash(parse_token(closing))


def test_error_receipts_validate_against_ap2s_receipt_model() -> None:
    errors = [v for v in VECTORS if v["expected_status"] == "Error"]
    assert errors
    for v in errors:
        CheckoutReceipt.model_validate(verify_jwt(v["receipt"], JWK(**v["verifier_jwk"])))


def test_a_wrong_key_is_rejected() -> None:
    v = VECTORS[0]
    with pytest.raises(Exception):
        verify_jwt(v["receipt"], JWK.generate(kty="EC", crv="P-256"))
