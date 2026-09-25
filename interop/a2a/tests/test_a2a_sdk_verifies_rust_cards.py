"""The official a2a-sdk's signature verifier accepts Agent Cards signed in Rust.

Vectors: testdata/rust/cards.json (`cargo run -p a2a-gov-card --example gen_card_vectors`).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from a2a.types import a2a_pb2
from a2a.utils.signing import InvalidSignaturesError, create_signature_verifier
from google.protobuf import json_format
from jwt import PyJWK

V = {v["name"]: v for v in json.loads((Path(__file__).resolve().parents[3] / "testdata" / "rust" / "cards.json").read_text())["vectors"]}


def verify(name: str) -> None:
    v = V[name]
    key = PyJWK(v["jwk"], algorithm="ES256")
    verifier = create_signature_verifier(lambda kid, _jku: key if kid == v["kid"] else None, ["ES256"])
    verifier(json_format.ParseDict(v["card"], a2a_pb2.AgentCard()))


@pytest.mark.parametrize("name", ["plain", "unicode"])
def test_sdk_verifies_rust_signed_cards(name: str) -> None:
    verify(name)


def test_the_sdk_rejects_a_spec_form_signature_over_an_empty_required_field() -> None:
    # Known divergence: A2A §8.4.1 keeps REQUIRED fields even when empty; the
    # a2a-sdk drops them before verifying, so the payloads differ.
    with pytest.raises(InvalidSignaturesError):
        verify("empty-description")
