"""Google's AP2 SDK must accept chains minted by a2a-gov-mandate.

Vectors: testdata/rust/access_chains.json, written by
`cargo run -p a2a-gov-mandate --example gen_vectors`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from ap2.sdk.mandate import MandateClient
from jwcrypto.jwk import JWK

VECTORS = json.loads(
    (Path(__file__).resolve().parents[3] / "testdata" / "rust" / "access_chains.json").read_text()
)["vectors"]


def verify(v: dict[str, Any], chain: str) -> list[dict[str, Any]]:
    surface = JWK(**v["trusted_surface_jwk"])
    return MandateClient().verify(
        chain,
        key_or_provider=lambda _tok: surface,
        expected_aud=v["aud"],
        expected_nonce=v["nonce"],
        current_time=v["issued_at"],
    )


def content(payload: dict[str, Any]) -> dict[str, Any]:
    return {k: val for k, val in payload.items() if k != "_sd"}


def test_enough_vectors() -> None:
    assert len(VECTORS) >= 20


@pytest.mark.parametrize("v", VECTORS, ids=lambda v: v["chain"][:12])
def test_one_hop_chain(v: dict[str, Any]) -> None:
    open_payload, closed_payload = verify(v, v["chain"])
    assert content(open_payload) == v["expected_open"]
    assert content(closed_payload) == v["expected_closed"]


@pytest.mark.parametrize("v", VECTORS, ids=lambda v: v["chain"][:12])
def test_two_hop_chain(v: dict[str, Any]) -> None:
    open_payload, delegated, closed_payload = verify(v, v["two_hop_chain"])
    assert content(open_payload) == v["expected_open"]
    assert content(delegated) == v["expected_delegated"]
    assert content(closed_payload) == v["expected_closed"]


def test_ap2_rejects_a_wrong_nonce() -> None:
    v = VECTORS[0]
    with pytest.raises(Exception, match="nonce"):
        verify({**v, "nonce": "other"}, v["chain"])
