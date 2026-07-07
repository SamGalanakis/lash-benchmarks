# Lash Benchmarks

External benchmark harnesses for Lash.

The Rust runners (`bench/*/runner`) depend on Lash from the latest GitHub
release tag pinned in the workspace `Cargo.toml` (the facade crate is
`lash`). The current pin is `v0.1.0-alpha.85`.

The `lash` CLI binary that drives Terminal Bench is **not** published to
crates.io (the `lash-cli` crate is `publish = false`), so the Terminal Bench
scripts install it from the matching Git tag pinned in `lash-pin.env`
(`LASH_GIT_TAG`). Keep that tag in sync with the workspace dependency tag
above.

## Layout

- `bench/` contains the benchmark-specific harnesses.
- `scripts/` contains shared Terminal Bench runners and result viewers.
- `Cargo.toml` defines the benchmark runner workspace.

## Verification

```sh
cargo check --workspace --all-targets
```
