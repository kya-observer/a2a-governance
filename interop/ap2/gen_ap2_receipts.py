"""Sign checkout and payment receipts with Google's AP2 SDK for the Rust tests.

Keys are generated per run and exist only to verify these vectors.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from ap2.sdk.jwt_helper import create_jwt
from ap2.sdk.receipt_wrapper import ReceiptClient
from jwcrypto.jwk import JWK

OUT = Path(__file__).resolve().parents[2] / "testdata" / "ap2" / "receipts.json"


def main() -> None:
    client = ReceiptClient()
    vectors = []
    for i in range(6):
        key = JWK.generate(kty="EC", crv="P-256", kid="merchant-1")
        receipt = client.create_checkout_receipt(
            merchant="https://merchant.example.org", reference=f"ref-{i}", order_id=f"order-{i}"
        )
        payload = json.loads(receipt.model_dump_json(exclude_none=True))
        token = create_jwt({"alg": "ES256", "typ": "JWT", "kid": "merchant-1"}, payload, key)
        vectors.append({"receipt": token, "verifier_jwk": json.loads(key.export_public()), "expected": payload})
    OUT.write_text(
        json.dumps(
            {
                "description": "Checkout receipts signed with Google's AP2 Python SDK (commit e1ea56d). Test keys only.",
                "vectors": vectors,
            },
            indent=2,
        )
        + "\n"
    )
    print(f"wrote {OUT}", file=sys.stderr)


if __name__ == "__main__":
    main()
