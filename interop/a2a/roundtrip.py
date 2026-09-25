"""Re-serialize the Rust vectors through the a2a-sdk's protobuf types, as any
protobuf-based peer would, and write them back for the Rust readers.

Output: testdata/a2a/binding_roundtrip.json.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from a2a.types import a2a_pb2
from google.protobuf import json_format

ROOT = Path(__file__).resolve().parents[2]
V = json.loads((ROOT / "testdata" / "rust" / "binding.json").read_text())


def roundtrip(obj: dict, message_type) -> dict:
    return json_format.MessageToDict(json_format.ParseDict(obj, message_type()))


def main() -> None:
    out = {
        "description": "testdata/rust/binding.json after a2a-sdk 1.1.5 ParseDict + MessageToDict.",
        "task_status": {k: roundtrip(v, a2a_pb2.TaskStatus) for k, v in V["task_status"].items()},
        "message": {k: roundtrip(v, a2a_pb2.Message) for k, v in V["message"].items()},
        "artifact": roundtrip(V["artifact"], a2a_pb2.Artifact),
    }
    path = ROOT / "testdata" / "a2a" / "binding_roundtrip.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=2) + "\n")
    print(f"wrote {path}", file=sys.stderr)


if __name__ == "__main__":
    main()
