"""Mint a non-payment access mandate chain with Google's AP2 SDK.

The output is a test vector that the Rust verifier must accept. The keys are
generated per run and exist only to verify these vectors; never reuse them.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

from ap2.sdk.mandate import MandateClient
from ap2.sdk.sdjwt import kb_sd_jwt
from ap2.sdk.sdjwt.common import parse_token
from jwcrypto.jwk import JWK
from pydantic import BaseModel, Field

VECTORS = Path(__file__).resolve().parents[2] / "testdata" / "ap2"
AUD = "https://agent.example.org/a2a"
NONCE = "n-0S6_WzA2Mj"


class Cnf(BaseModel):
    jwk: dict[str, Any]


class OpenAccessMandate(BaseModel):
    vct: str = "mandate.access.1"
    cnf: Cnf
    iat: int
    exp: int
    constraints: list[dict[str, Any]] = Field(
        json_schema_extra={"x-selectively-disclosable-array": True}
    )


class ClosedAccessMandate(BaseModel):
    vct: str = "mandate.access.1"
    method: str
    task_id: str
    action_hash: str


def public_jwk(key: JWK) -> dict[str, Any]:
    return json.loads(key.export_public())


class DelegatedAccessMandate(BaseModel):
    """Intermediate hop: narrows the open mandate and delegates to a sub-agent."""

    vct: str = "mandate.access.1"
    cnf: Cnf
    constraints: list[dict[str, Any]]


def mint(index: int) -> dict[str, Any]:
    surface_key = JWK.generate(kty="EC", crv="P-256", kid="trusted-surface-1")
    agent_key = JWK.generate(kty="EC", crv="P-256")
    now = int(time.time())

    open_mandate = OpenAccessMandate(
        cnf=Cnf(jwk=public_jwk(agent_key)),
        iat=now,
        exp=now + 7200,
        constraints=[
            {
                "type": "access.authorization_details",
                "authorization_details": [
                    {"type": "calendar", "actions": ["read.freebusy"], "fields": ["start", "end"]}
                ],
            },
            {"type": "access.purpose", "purpose": "dpv:ServiceProvision"},
            {"type": "access.release", "release": "answer-only"},
            {"type": "access.max_uses", "max_uses": 3},
        ],
    )
    client = MandateClient()
    open_token = client.create(payloads=[open_mandate], issuer_key=surface_key)

    closed = ClosedAccessMandate(
        method="SendMessage",
        task_id="task-7f3c",
        action_hash="3WiKMabE8NRYJgveUbyAZ3pBqRfPrWwGDbOyvbO1eYA",
    )
    chain = client.present(
        holder_key=agent_key,
        mandate_token=open_token,
        payloads=[closed],
        aud=AUD,
        nonce=NONCE,
    )

    # Self-check with AP2's own verifier before writing anything.
    client.verify(
        chain,
        key_or_provider=lambda _tok: surface_key,
        expected_aud=AUD,
        expected_nonce=NONCE,
    )

    sub_agent_key = JWK.generate(kty="EC", crv="P-256")
    delegated = DelegatedAccessMandate(
        cnf=Cnf(jwk=public_jwk(sub_agent_key)),
        constraints=[{"type": "access.max_uses", "max_uses": 1}],
    )
    # MandateClient.present() extends one hop only; multi-hop chains are built
    # with kb_sd_jwt.create and joined by hand, as AP2's own chain tests do.
    delegate_segment = kb_sd_jwt.create(
        prev_token=parse_token(open_token),
        holder_key=agent_key,
        payload=delegated,
        aud="https://sub-agent.example.org/a2a",
        nonce=f"n-delegate-{index}",
    ).sd_jwt_issuance
    closing_segment = kb_sd_jwt.create(
        prev_token=parse_token(delegate_segment),
        holder_key=sub_agent_key,
        payload=closed,
        aud=AUD,
        nonce=NONCE,
    ).sd_jwt_issuance
    two_hop = f"{open_token[:-1]}~~{delegate_segment[:-1]}~~{closing_segment}"
    client.verify(
        two_hop,
        key_or_provider=lambda _tok: surface_key,
        expected_aud=AUD,
        expected_nonce=NONCE,
    )

    return {
                "issued_at": now,
                "trusted_surface_jwk": public_jwk(surface_key),
                "agent_jwk": public_jwk(agent_key),
                "aud": AUD,
                "nonce": NONCE,
                "open_mandate": open_token,
                "chain": chain,
                "two_hop_chain": two_hop,
                "sub_agent_jwk": public_jwk(sub_agent_key),
                "expected_open": json.loads(open_mandate.model_dump_json()),
                "expected_delegated": json.loads(delegated.model_dump_json()),
                "expected_closed": json.loads(closed.model_dump_json()),
    }


def main() -> None:
    VECTORS.mkdir(parents=True, exist_ok=True)
    out = VECTORS / "access_chains.json"
    out.write_text(
        json.dumps(
            {
                "description": "Non-payment access mandate chains minted by Google's AP2 Python "
                "SDK (commit e1ea56d): one-hop (open -> closed) and two-hop (open -> delegated "
                "-> closed). Fresh test keys per vector; never reuse them.",
                "vectors": [mint(i) for i in range(25)],
            },
            indent=2,
        )
        + "\n"
    )
    print(f"wrote {out}", file=sys.stderr)


if __name__ == "__main__":
    main()
