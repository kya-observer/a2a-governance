# A2A Delegation Governance

**Reference implementation of an [A2A](https://a2a-protocol.org) extension for
mandate-based in-task authorization.**

A2A lets an agent pause a task in `TASK_STATE_AUTH_REQUIRED` when it needs
authorization, but it leaves open what the approval produces. §7.6.4 of the spec says
the scope, validity and revocation of that credential must be defined by the
implementation or by an extension. This extension defines it:

1. The agent asks for a **mandate**: what it wants to do, for what purpose, and for how
   long.
2. The user approves it on a **trusted surface** outside the agent and its LLM. The
   surface signs an open mandate bound to the calling agent's key.
3. The agent continues the task, presenting the mandate plus a **closing hop** bound to
   that one call.
4. The verifier checks the chain, applies the constraints, and returns a signed
   **receipt**.

Calls refused or paused before a task exists get a standard error profile: **Deny**
(`-31000`) or **Challenge** (`-31001`) with an approval link.

Mandates use the Agent Authorization model of **AP2 v0.2**, now developed at the FIDO
Alliance. This project adds the A2A binding, general-purpose (non-payment) constraint
types, and a decision point. Interoperability with Google's AP2 SDK is tested in both
directions.

> **Status: in development (v0.1, unreleased).** Implemented and tested: the extension
> surface, AP2-compatible mandates, receipts and the receipt log, the decision engine,
> the A2A message shapes, and signed Agent Cards. In progress: Python bindings for agent
> developers, an example agent, and gateway integration. Expect breaking changes.

## What's here

| Path | What it is |
|---|---|
| [`crates/a2a-gov-extension`](crates/a2a-gov-extension) | The A2A side: Agent Card declaration, `A2A-Extensions` activation, the Deny/Challenge error profile |
| [`crates/a2a-gov-card`](crates/a2a-gov-card) | Signed Agent Cards (A2A §8.4): RFC 8785, default-value removal generated from `a2a.proto`, ES256, fingerprints for pinning |
| [`crates/a2a-gov-binding`](crates/a2a-gov-binding) | The extension's A2A v1.0 message shapes: mandate request in `TASK_STATE_AUTH_REQUIRED`, continuation with a presentation, receipt artifact |
| [`crates/a2a-gov-mandate`](crates/a2a-gov-mandate) | Mandate chains in AP2's wire format: issue, delegate, present, verify |
| [`crates/a2a-gov-pdp`](crates/a2a-gov-pdp) | The decision engine: Pass / Deny / Challenge for a concrete call, with constraints, use limits, nonces and revocation behind store traits |
| [`crates/a2a-gov-receipt`](crates/a2a-gov-receipt) | Signed Mandate Receipts (AP2-compatible) and a hash-chained receipt log |
| [`interop/ap2`](interop/ap2) | Cross-verification against Google's AP2 Python SDK |
| [`interop/a2a`](interop/a2a) | The A2A shapes checked with the official `a2a-sdk` |
| [`scripts/mutation-check.py`](scripts/mutation-check.py) | Mutation testing for every security check |
| [`testdata`](testdata) | Vectors minted by AP2 and by this implementation |
| [`docs`](docs) | [Wire format](docs/wire-format.md), [Agent Cards](docs/agent-cards.md), [security properties](docs/security.md), [references](docs/references.md) |

## Quickstart

```sh
cargo test --workspace                        # Rust suite
cd interop/ap2 && uv sync && uv run pytest    # AP2 SDK verifies our chains and receipts
cd interop/a2a && uv sync && uv run pytest    # a2a-sdk parses our A2A shapes
python3 scripts/mutation-check.py             # every security check is load-bearing
```

Regenerate the vectors:

```sh
cargo run -p a2a-gov-mandate --example gen_vectors    # ours, for AP2
cd interop/ap2 && uv run python gen_ap2_vectors.py    # AP2's, for us
```

## How we know it works

- **Both directions of interop.** Google's AP2 SDK verifies every chain and receipt this
  project mints, and this project verifies every chain and receipt AP2 mints: one-hop
  and two-hop, several disclosure modes, high-S ECDSA signatures. The official
  `a2a-sdk` parses every A2A shape strictly, and its re-serialization reads back
  unchanged. CI re-mints the vectors on every run.
- **Spec-sourced test values.** Disclosure digests come from RFC 9901's own examples;
  error-profile tests cite the A2A section they enforce.
- **Every security check is load-bearing.** `scripts/mutation-check.py` disables each
  check in turn and fails if the tests still pass; CI runs it. The threat-to-test map is
  in [docs/security.md](docs/security.md), including what isn't covered.
- **Reviewed adversarially.** An independent review found three blockers (withheld
  disclosures, signature malleability, mandates without `exp`). Each is now reproduced
  by a test and fixed; see the commit history.
- **Stricter than required, and documented.** Where we refuse something AP2 accepts, the
  reason is in [docs/wire-format.md](docs/wire-format.md).

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Contributions need a DCO
sign-off; see [CONTRIBUTING.md](CONTRIBUTING.md).
