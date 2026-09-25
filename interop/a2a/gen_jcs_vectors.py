"""Canonicalize random doubles and random JSON with the official a2a-sdk's
RFC 8785 implementation, for the Rust canonicalizer to match exactly.

Output: testdata/a2a/jcs.json. Seeded, so the file is reproducible.
"""

from __future__ import annotations

import json
import math
import random
import struct
import sys
from pathlib import Path

from a2a.utils._jcs import canonicalize

OUT = Path(__file__).resolve().parents[2] / "testdata" / "a2a" / "jcs.json"
rng = random.Random(8785)


def random_double() -> float:
    while True:
        x = struct.unpack("<d", struct.pack("<Q", rng.getrandbits(64)))[0]
        if math.isfinite(x):
            return x


def scalar() -> str:
    """A random Unicode scalar value (never a lone surrogate)."""
    while True:
        c = rng.randrange(0x20, 0x2FFFF)
        if not 0xD800 <= c <= 0xDFFF:
            return chr(c)


def random_json(depth: int = 0):
    kind = rng.randrange(7 if depth < 4 else 4)
    if kind == 0:
        return random_double()
    if kind == 1:
        return rng.randrange(-(2**53) + 1, 2**53)
    if kind == 2:
        return "".join(chr(rng.choice([rng.randrange(0x20), rng.randrange(0x20, 0x7F), rng.randrange(0x80, 0xD800), rng.randrange(0xE000, 0x110000)])) for _ in range(rng.randrange(8)))
    if kind == 3:
        return rng.choice([None, True, False, 0, -0.0, 1.5])
    if kind == 4:
        return [random_json(depth + 1) for _ in range(rng.randrange(4))]
    keys = ["".join(scalar() for _ in range(rng.randrange(1, 5))) for _ in range(rng.randrange(5))]
    return {k: random_json(depth + 1) for k in keys}


def main() -> None:
    doubles = [random_double() for _ in range(20000)]
    ties = [1424953923781206.25, 0.5, 2.5, 1e23, 5e-324, 9007199254740993.0]
    numbers = [{"bits": struct.unpack("<Q", struct.pack("<d", x))[0], "jcs": canonicalize(x)} for x in doubles + ties]
    documents = []
    for _ in range(2000):
        doc = random_json()
        documents.append({"json": json.dumps(doc, ensure_ascii=False), "jcs": canonicalize(doc)})
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({"description": "a2a-sdk 1.1.5 RFC 8785 output for seeded random input.", "numbers": numbers, "documents": documents}) + "\n")
    print(f"wrote {OUT}: {len(numbers)} numbers, {len(documents)} documents", file=sys.stderr)


if __name__ == "__main__":
    main()
