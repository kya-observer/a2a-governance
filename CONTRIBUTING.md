# Contributing

Contributions are welcome: bug reports, spec feedback, interop results from other
implementations, and code.

## Developer Certificate of Origin

Every commit must be signed off, certifying the [DCO](https://developercertificate.org):

```sh
git commit -s
```

That adds `Signed-off-by: Your Name <you@example.com>`. No CLA is required.

## Before you open a pull request

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cd interop/ap2 && uv run pytest
```

- Security checks need a test that fails without them. Say which check your test
  protects.
- Test values from a specification should cite the section they come from.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/).

## Reporting a vulnerability

Please don't open a public issue. Use GitHub's private vulnerability reporting on this
repository.
