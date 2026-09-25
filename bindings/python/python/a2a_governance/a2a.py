"""Helpers for the official `a2a-sdk` (install with `a2a-governance[a2a]`).

The in-task flow, from the agent's side:

    key = AgentKey.generate()
    msg = hello(key, "What have I read about Rust?", context_id="c1")
    # send msg; the task comes back in TASK_STATE_AUTH_REQUIRED
    state = auth_state(task)          # {"state": "pending", "approvalUrl": ...}
    # the user approves out of band; poll or subscribe until:
    state = auth_state(task)          # {"state": "approved", "mandate": ...}
    msg = continuation(task, key, closed, "Continuing")
    # send msg; then
    receipt = receipt_meta(task)      # {"receipt": ..., "nextNonce": ...}
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from a2a.types import a2a_pb2
from google.protobuf import json_format

from . import AgentKey, _native


def _to_json(message: Any) -> str:
    return json.dumps(json_format.MessageToDict(message))


def hello(key: AgentKey, text: str, *, context_id: str, message_id: str | None = None) -> a2a_pb2.Message:
    """The first message, activating the extension and offering the agent's key."""
    raw = _native.hello_message(message_id or str(uuid.uuid4()), context_id, text, json.dumps(key.public_jwk))
    return json_format.ParseDict(json.loads(raw), a2a_pb2.Message())


def auth_state(task: a2a_pb2.Task) -> dict[str, Any] | None:
    """The extension's state on a task: pending (with the approval link),
    approved (with the open mandate), denied, or `None` if the task carries none."""
    raw = _native.read_status(_to_json(task.status))
    return None if raw is None else json.loads(raw)


def continuation(
    task: a2a_pb2.Task,
    key: AgentKey,
    closed: dict[str, Any],
    text: str,
    *,
    message_id: str | None = None,
    iat: int | None = None,
) -> a2a_pb2.Message:
    """Continues an approved task with a presentation for this call."""
    state = auth_state(task)
    if not state or state.get("state") != "approved":
        raise ValueError("the task has no approved mandate yet")
    chain = key.present(state["mandate"], closed, state["aud"], state["nonce"], iat)
    raw = _native.continuation_message(message_id or str(uuid.uuid4()), task.id, task.context_id, text, chain, state["nonce"])
    return json_format.ParseDict(json.loads(raw), a2a_pb2.Message())


def receipt_meta(task: a2a_pb2.Task) -> dict[str, Any] | None:
    """The receipt (and next nonce) from the task's result artifacts, if any."""
    for artifact in task.artifacts:
        raw = _native.read_receipt(_to_json(artifact))
        if raw is not None:
            return json.loads(raw)
    return None
