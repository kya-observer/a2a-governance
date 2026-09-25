"""The official a2a-sdk (1.1.5) accepts every shape the extension emits.

`json_format.ParseDict` is protobuf's strict JSON parser: unknown fields and
invalid enum values fail. (It accepts both `taskId` and `task_id`, so ProtoJSON
naming is checked on the Rust side.)
Vectors: testdata/rust/binding.json (`cargo run -p a2a-gov-binding --example gen_binding_vectors`).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from a2a.extensions.common import find_extension_by_uri, get_requested_extensions
from a2a.types import a2a_pb2
from google.protobuf import json_format

ROOT = Path(__file__).resolve().parents[3]
V = json.loads((ROOT / "testdata" / "rust" / "binding.json").read_text())
URI = V["extension_uri"]


def parse(obj: dict, message_type):
    return json_format.ParseDict(obj, message_type(), ignore_unknown_fields=False)


@pytest.mark.parametrize("name", ["pending", "approved", "denied"])
def test_task_statuses(name: str) -> None:
    status = parse(V["task_status"][name], a2a_pb2.TaskStatus)
    expected = a2a_pb2.TASK_STATE_REJECTED if name == "denied" else a2a_pb2.TASK_STATE_AUTH_REQUIRED
    assert status.state == expected
    assert URI in status.message.extensions
    assert status.message.role == a2a_pb2.ROLE_AGENT
    assert json_format.MessageToDict(status.message.metadata)[URI]["state"] == name


@pytest.mark.parametrize("name", ["hello", "continuation"])
def test_messages(name: str) -> None:
    message = parse(V["message"][name], a2a_pb2.Message)
    assert message.role == a2a_pb2.ROLE_USER
    assert list(message.extensions) == [URI]


def test_artifact_and_task() -> None:
    parse(V["artifact"], a2a_pb2.Artifact)
    task = parse(V["task"], a2a_pb2.Task)
    assert task.status.state == a2a_pb2.TASK_STATE_AUTH_REQUIRED
    assert task.artifacts[0].artifact_id == "a1"


def test_agent_card_declares_the_extension() -> None:
    card = parse(V["agent_card"], a2a_pb2.AgentCard)
    ext = find_extension_by_uri(card, URI)
    assert ext is not None and ext.required
    assert json_format.MessageToDict(ext.params)["mandateFormats"] == ["dc+sd-jwt"]


def test_the_sdk_parses_activation_the_same_way() -> None:
    assert URI in get_requested_extensions([f"https://example.com/ext/geo/v1, {URI}"])


def test_an_unknown_field_would_be_caught() -> None:
    # Guards the strictness this suite relies on. Note that protobuf also accepts
    # the proto field name (`task_id`) as well as the ProtoJSON name (`taskId`),
    # so ProtoJSON naming is enforced by the Rust tests, not here.
    bad = json.loads(json.dumps(V["message"]["continuation"]))
    bad["taskIdd"] = bad.pop("taskId")
    with pytest.raises(json_format.ParseError):
        parse(bad, a2a_pb2.Message)
