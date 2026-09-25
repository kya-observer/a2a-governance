"""Sign Agent Cards with the official a2a-sdk (1.1.5), for the Rust verifier.

Output: testdata/a2a/cards.json. Keys are generated per run; test use only.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from a2a.types import a2a_pb2
from a2a.utils.signing import create_agent_card_signer
from cryptography.hazmat.primitives.asymmetric import ec
from google.protobuf import json_format
from jwt.algorithms import ECAlgorithm

OUT = Path(__file__).resolve().parents[2] / "testdata" / "a2a" / "cards.json"

BASE = {
    "name": "Example vault agent",
    "description": "Answers questions about a reading history",
    "version": "0.1.0",
    "supportedInterfaces": [{"url": "https://vault.example.org/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}],
    "capabilities": {"streaming": False, "extensions": [{"uri": "https://example.org/ext/v1", "required": True, "params": {"mandateFormats": ["dc+sd-jwt"], "n": 3}}]},
    "defaultInputModes": ["text/plain"],
    "defaultOutputModes": ["text/plain"],
    "skills": [{"id": "reading", "name": "Reading", "description": "Answers from reading history", "tags": ["reading"]}],
}


def variant(name: str) -> dict:
    card = json.loads(json.dumps(BASE))
    if name == "empty-description":
        card["description"] = ""  # REQUIRED: §8.4.1 keeps it; the a2a-sdk drops it
    if name == "unicode":
        card["name"] = "Agent f\u00fcr Lesehistorie \u20ac"
    if name == "empty-param":
        card["capabilities"]["extensions"][0]["params"]["note"] = ""  # the a2a-sdk doesn't sign this
    return card


def main() -> None:
    vectors = []
    for name in ["plain", "empty-description", "unicode", "empty-param"]:
        private = ec.generate_private_key(ec.SECP256R1())
        jwk_private = ECAlgorithm.to_jwk(private, as_dict=True)
        public = {k: v for k, v in jwk_private.items() if k in ("kty", "crv", "x", "y")}
        signer = create_agent_card_signer(
            signing_key=private, protected_header={"kid": f"key-{name}", "alg": "ES256", "typ": "JOSE", "jku": None}
        )
        card = json_format.ParseDict(variant(name), a2a_pb2.AgentCard())
        signed = json_format.MessageToDict(signer(card))
        vectors.append({"name": name, "card": signed, "kid": f"key-{name}", "jwk": public})
    OUT.write_text(json.dumps({"description": "Agent Cards signed by a2a-sdk 1.1.5. Test keys only.", "vectors": vectors}, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {OUT}", file=sys.stderr)


if __name__ == "__main__":
    main()
