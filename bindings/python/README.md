# a2a-governance (Python)

Agent-side support for the A2A Delegation Governance extension: generate and store the
agent key, present an approved mandate for one call, recognize Deny/Challenge errors,
and verify receipts. The cryptography is the project's Rust implementation, via PyO3.

```sh
pip install "a2a-governance[a2a]"   # with helpers for the official a2a-sdk
```

See `a2a_governance.a2a` for the in-task flow with `a2a-sdk` types.
