# AP2 interop

Cross-verification between `a2a-gov-mandate` and Google's AP2 Python SDK, pinned to
commit `e1ea56d`. The PyPI package named `ap2` is **not** Google's, so the SDK is
installed from git.

```sh
uv sync
uv run pytest                     # AP2 verifies chains minted in Rust
uv run python gen_ap2_vectors.py  # mint vectors with AP2 for the Rust tests
```

Note that AP2's SDK appends presentation tokens to
`.venv/lib/python*/site-packages/ap2/.logs/mandate_operations.log`. They are test tokens
here, but don't run the SDK this way with real credentials.
