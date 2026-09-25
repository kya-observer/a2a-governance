"""Agent-side support for the A2A Delegation Governance extension.

The cryptography lives in Rust (`a2a-gov-*` crates); this package is a thin
layer over it. See `a2a_governance.a2a` for helpers built on the official
`a2a-sdk`.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from . import _native

EXTENSION_URI: str = _native.EXTENSION_URI

__all__ = ["EXTENSION_URI", "AgentKey", "Challenge", "Deny", "parse_error", "verify_receipt"]


class AgentKey:
    """The agent's P-256 key. Mandates are bound to it (`cnf.jwk`)."""

    def __init__(self, private_jwk: dict[str, Any]) -> None:
        self._private = json.dumps(private_jwk)
        self.public_jwk: dict[str, Any] = json.loads(_native.public_jwk(self._private))

    @classmethod
    def generate(cls, kid: str | None = None) -> AgentKey:
        return cls(json.loads(_native.generate_key(kid)))

    @classmethod
    def from_private_jwk(cls, jwk: dict[str, Any]) -> AgentKey:
        return cls(jwk)

    def private_jwk(self) -> dict[str, Any]:
        """The key for storage. Treat it as a secret."""
        return json.loads(self._private)

    def present(self, open_mandate: str, closed: dict[str, Any], aud: str, nonce: str, iat: int | None = None) -> str:
        """The presentation chain for one call: `open_mandate` plus a closing hop
        describing the call (`closed`), bound to the verifier's `aud` and `nonce`."""
        return _native.present(self._private, open_mandate, json.dumps(closed), aud, nonce, int(iat or time.time()))

    def __repr__(self) -> str:
        return f"AgentKey(public_jwk={self.public_jwk!r})"


@dataclass(frozen=True)
class Deny:
    reason: str
    message: str


@dataclass(frozen=True)
class Challenge:
    reason: str
    message: str
    challenge_id: str
    url: str


def parse_error(error: dict[str, Any], domain: str) -> Deny | Challenge | None:
    """Recognizes a governance Deny or Challenge in a JSON-RPC `error` object
    issued by `domain`. Returns `None` for any other error."""
    parsed = _native.parse_error(json.dumps(error), domain)
    if parsed is None:
        return None
    p = json.loads(parsed)
    if p["kind"] == "deny":
        return Deny(p["reason"], p["message"])
    return Challenge(p["reason"], p["message"], p["challengeId"], p["url"])


def verify_receipt(receipt: str, verifier_jwk: dict[str, Any], chain: str) -> dict[str, Any]:
    """Verifies a receipt's signature and that it refers to `chain`; returns its payload."""
    return json.loads(_native.verify_receipt(receipt, json.dumps(verifier_jwk), chain))
