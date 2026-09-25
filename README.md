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

> **Status: in development (v0.1, unreleased).** The extension surface and the mandate
> layer are implemented and tested. The decision point, receipts, the example agent and
> the gateway integration are in progress. Expect breaking changes.

## What's here

| Path | What it is |
|---|---|
| [`crates/a2a-gov-extension`](crates/a2a-gov-extension) | The A2A side: Agent Card declaration, `A2A-Extensions` activation, the Deny/Challenge error profile |
| [`crates/a2a-gov-mandate`](crates/a2a-gov-mandate) | Mandate chains in AP2's wire format: issue, delegate, present, verify |
| [`interop/ap2`](interop/ap2) | Cross-verification against Google's AP2 Python SDK |
| [`testdata`](testdata) | Vectors minted by AP2 and by this implementation |
| [`docs`](docs) | [Wire format](docs/wire-format.md), [security properties](docs/security.md), [references](docs/references.md) |

## Quickstart

```sh
cargo test --workspace                        # Rust suite
cd interop/ap2 && uv sync && uv run pytest    # AP2 SDK verifies our chains
```

Regenerate the vectors:

```sh
cargo run -p a2a-gov-mandate --example gen_vectors    # ours, for AP2
cd interop/ap2 && uv run python gen_ap2_vectors.py    # AP2's, for us
```

## How we know it works

- **Both directions of interop.** Google's AP2 SDK verifies every chain this crate mints,
  and this crate verifies every chain AP2 mints: one-hop and two-hop, across several
  selective-disclosure modes, including high-S ECDSA signatures.
- **Spec-sourced test values.** Disclosure digests come from RFC 9901's own examples;
  error-profile tests cite the A2A section they enforce.
- **Every security check is load-bearing.** Each check was disabled in turn and the
  suite rerun; all 18 mutations were caught. See [docs/security.md](docs/security.md).
- **Stricter than required, and documented.** Where we refuse something AP2 accepts, the
  reason is in [docs/wire-format.md](docs/wire-format.md).

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Contributions need a DCO
sign-off; see [CONTRIBUTING.md](CONTRIBUTING.md).
