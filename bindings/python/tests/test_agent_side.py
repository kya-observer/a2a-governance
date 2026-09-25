"""The agent side of the extension, end to end against the Rust verifier.

`oracle` runs `crates/a2a-gov-pdp/examples/pytest_oracle.rs`: it issues an open
mandate bound to the agent's key, then runs the real decision engine on the
agent's continuation message.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
from a2a.types import a2a_pb2
from google.protobuf import json_format

from a2a_governance import EXTENSION_URI, AgentKey, Challenge, Deny, parse_error, verify_receipt
from a2a_governance.a2a import auth_state, continuation, hello, receipt_meta

ROOT = Path(__file__).resolve().parents[3]


def oracle(command: str, payload: dict[str, Any]) -> dict[str, Any]:
    out = subprocess.run(
        ["cargo", "run", "-q", "-p", "a2a-gov-pdp", "--example", "pytest_oracle", "--", command],
        input=json.dumps(payload), capture_output=True, text=True, cwd=ROOT, check=True,
    )
    return json.loads(out.stdout)


def approved_task(key: AgentKey) -> tuple[a2a_pb2.Task, dict[str, Any]]:
    issued = oracle("issue", {"agent_jwk": key.public_jwk})
    task = a2a_pb2.Task(id="t1", context_id="c1")
    task.status.CopyFrom(json_format.ParseDict(issued["status"], a2a_pb2.TaskStatus()))
    return task, issued


def closed(call: dict[str, Any]) -> dict[str, Any]:
    return {"vct": "mandate.access.1", **call}


# --- Keys ------------------------------------------------------------------------------------


def test_keys_round_trip_and_never_print_the_private_scalar() -> None:
    key = AgentKey.generate(kid="agent-1")
    private = key.private_jwk()
    assert private["kid"] == "agent-1" and "d" in private
    assert AgentKey.from_private_jwk(private).public_jwk == key.public_jwk
    assert "d" not in key.public_jwk
    assert private["d"] not in repr(key)


def test_a_malformed_private_key_is_refused() -> None:
    with pytest.raises(ValueError):
        AgentKey.from_private_jwk({"kty": "EC", "crv": "P-256"})


# --- Messages ----------------------------------------------------------------------------------


def test_hello_activates_the_extension_and_offers_the_key() -> None:
    key = AgentKey.generate()
    msg = hello(key, "What have I read about Rust?", context_id="c1")
    assert list(msg.extensions) == [EXTENSION_URI]
    meta = json_format.MessageToDict(msg.metadata)[EXTENSION_URI]
    assert meta["holderJwk"] == key.public_jwk


# --- End to end --------------------------------------------------------------------------------


def test_an_approved_mandate_is_presented_and_the_receipt_verifies() -> None:
    key = AgentKey.generate()
    task, issued = approved_task(key)
    assert auth_state(task)["state"] == "approved"
    msg = continuation(task, key, closed(issued["call"]), "Continuing with the mandate")
    assert msg.task_id == "t1" and list(msg.extensions) == [EXTENSION_URI]

    result = oracle("decide", {"message": json_format.MessageToDict(msg), "surface_jwk": issued["surface_jwk"], "call": issued["call"]})
    assert result["decision"] == "pass", result

    task.artifacts.append(json_format.ParseDict(result["artifact"], a2a_pb2.Artifact()))
    meta = receipt_meta(task)
    payload = verify_receipt(meta["receipt"], result["verifier_jwk"], result["chain"])
    assert payload["status"] == "Success"


def test_a_presentation_for_a_different_call_is_denied() -> None:
    key = AgentKey.generate()
    task, issued = approved_task(key)
    other = dict(issued["call"], authorization_details=[{"type": "reading", "actions": ["search"], "fields": ["body"]}])
    msg = continuation(task, key, closed(other), "Asking for more")
    result = oracle("decide", {"message": json_format.MessageToDict(msg), "surface_jwk": issued["surface_jwk"], "call": issued["call"]})
    assert (result["decision"], result["reason"]) == ("deny", "INVALID_MANDATE")


def test_a_mandate_bound_to_another_key_is_useless() -> None:
    owner, thief = AgentKey.generate(), AgentKey.generate()
    task, issued = approved_task(owner)
    msg = continuation(task, thief, closed(issued["call"]), "Borrowing the mandate")
    result = oracle("decide", {"message": json_format.MessageToDict(msg), "surface_jwk": issued["surface_jwk"], "call": issued["call"]})
    assert (result["decision"], result["reason"]) == ("deny", "INVALID_CREDENTIAL")


def test_a_receipt_for_another_presentation_is_refused() -> None:
    key = AgentKey.generate()
    task, issued = approved_task(key)
    msg = continuation(task, key, closed(issued["call"]), "Continuing")
    result = oracle("decide", {"message": json_format.MessageToDict(msg), "surface_jwk": issued["surface_jwk"], "call": issued["call"]})
    task.artifacts.append(json_format.ParseDict(result["artifact"], a2a_pb2.Artifact()))
    other_task, other_issued = approved_task(key)
    other_chain = key.present(auth_state(other_task)["mandate"], closed(other_issued["call"]), "https://vault.example.org/a2a", "n")
    with pytest.raises(ValueError):
        verify_receipt(receipt_meta(task)["receipt"], result["verifier_jwk"], other_chain)


def test_continuing_before_approval_is_an_error() -> None:
    key = AgentKey.generate()
    with pytest.raises(ValueError):
        continuation(a2a_pb2.Task(id="t", context_id="c"), key, {}, "too early")


# --- Deny / Challenge errors ------------------------------------------------------------------


def test_governance_errors_are_recognized_and_others_are_not() -> None:
    challenge = {
        "code": -31001, "message": "approval required",
        "data": [
            {"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "APPROVAL_REQUIRED",
             "domain": "vault.example.org", "metadata": {"challengeId": "ch_1"}},
            {"@type": "type.googleapis.com/google.rpc.Help",
             "links": [{"description": "approval required", "url": "https://approve.example.org/c/ch_1"}]},
        ],
    }
    assert parse_error(challenge, "vault.example.org") == Challenge(
        "APPROVAL_REQUIRED", "approval required", "ch_1", "https://approve.example.org/c/ch_1"
    )
    deny = {"code": -31000, "message": "no", "data": [
        {"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "INVALID_MANDATE", "domain": "vault.example.org"}]}
    assert parse_error(deny, "vault.example.org") == Deny("INVALID_MANDATE", "no")
    assert parse_error(deny, "other.example") is None
    task_not_found = {"code": -32001, "message": "Task not found", "data": [
        {"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "TASK_NOT_FOUND", "domain": "a2a-protocol.org"}]}
    assert parse_error(task_not_found, "a2a-protocol.org") is None
