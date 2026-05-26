# Lash Benchmarks

External benchmark harnesses for Lash.

The Rust runners and Terminal Bench scripts are pinned to a specific Lash Git
revision in `lash-pin.env`. Update `LASH_GIT_REV` when intentionally moving the
benchmarks to a newer Lash commit.

## Layout

- `bench/` contains the benchmark-specific harnesses.
- `scripts/` contains shared Terminal Bench runners and result viewers.
- `Cargo.toml` defines the benchmark runner workspace.

## Verification

```sh
cargo check --workspace --all-targets
```
